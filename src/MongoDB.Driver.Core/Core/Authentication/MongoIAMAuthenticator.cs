/* Copyright 2018–present MongoDB Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Bson.IO;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Driver.Core.Authentication.Vendored;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Misc;

namespace MongoDB.Driver.Core.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class AwsSigV4
    {
        private static byte[] HMac(byte[] keyBytes, byte[] bytes)
        {
            using (HMACSHA256 hash = new HMACSHA256(keyBytes))
            {
                return hash.ComputeHash(bytes);
            }
        }

        private static string Hash(string str)
        {
            byte[] bytes = ASCIIEncoding.ASCII.GetBytes(str);
            using (SHA256 hash = SHA256.Create())
            {
                var a = hash.ComputeHash(bytes);

                return toHexString(a);
            }
        }

        private static string toHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }


        private static byte[] getSignatureKey(string secretKey, string datestamp,
                                                              string region,
                                                              string service)
        {
            string key = "AWS4" + secretKey;
            const string request = "aws4_request";
            byte[] kDateBlock = HMac(ASCIIEncoding.ASCII.GetBytes(key), ASCIIEncoding.ASCII.GetBytes(datestamp));
            byte[] kRegionBlock = HMac(kDateBlock, ASCIIEncoding.ASCII.GetBytes(region));
            byte[] kServiceBlock = HMac(kRegionBlock, ASCIIEncoding.ASCII.GetBytes(service));
            byte[] kSigningBlock = HMac(kServiceBlock, ASCIIEncoding.ASCII.GetBytes(request));
            return kSigningBlock;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="accessKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="securityToken"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static Tuple<string, string> SignRequest(string accessKey, string secretKey, string securityToken, byte[] salt)
        {
            return SignRequest(DateTime.UtcNow, accessKey, secretKey, securityToken, salt);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="now"></param>
        /// <param name="accessKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="securityToken"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static Tuple<string, string> SignRequest(DateTime now, string accessKey, string secretKey, string securityToken, byte[] salt)
        {
            const string method = "POST";

            const string service = "sts";
            const string region = "us-east-1";  //  TODO - Need to locate region

            // IMPORTANT: host may vary from the default sts.amazonaws.com. The service is always sts no matter what the host is
            var host = String.Format(CultureInfo.InvariantCulture, "{0}.amazonaws.com", service);

            const string contentType = "application/x-www-form-urlencoded";
            const string body = "Action=GetCallerIdentity&Version=2011-06-15";

            string timestamp = now.ToString("yyyyMMddTHHmmssZ");
            // constexpr auto timestampFormat = "%Y%m%dT%H%M%SZ"_sd;
            string datestamp = now.ToString("yyyyMMdd");
            //constexpr auto dateFormat = "%Y%m%d"_sd;

            /* -- Task 1: Create a canonical request -- */

            StringBuilder canonicalHeadersBuilder = new StringBuilder();
            StringBuilder signedHeadersBuilder = new StringBuilder();

            canonicalHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, "content-length:{0}\ncontent-type:{1}\nhost:{2}\nx-amz-date:{3}\n",
                body.Length, contentType, host, timestamp);
            signedHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, "content-length;content-type;host;x-amz-date");

            if (securityToken != null)
            {
                canonicalHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, "x-amz-security-token:{0}\n", securityToken);
                signedHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, ";x-amz-security-token");
            }

            canonicalHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, "x-mongodb-server-salt:{0}\n", System.Convert.ToBase64String(salt));
            signedHeadersBuilder.AppendFormat(CultureInfo.InvariantCulture, ";x-mongodb-server-salt");

            string canonicalHeaders = canonicalHeadersBuilder.ToString();
            string signedHeaders = signedHeadersBuilder.ToString();

            string payloadHash = Hash(body);

            string canonicalRequest = String.Format(CultureInfo.InvariantCulture, "{0}\n{1}\n{2}\n{3}\n{4}\n{5}",
                method, "/", "", canonicalHeaders, signedHeaders, payloadHash);

            /* -- Task 2: Create the string to sign -- */

            string algorithm = "AWS4-HMAC-SHA256";
            string credentialScope = String.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}/aws4_request", datestamp, region, service);

            string stringToSign = String.Format(CultureInfo.InvariantCulture, "{0}\n{1}\n{2}\n{3}",
                algorithm,
                timestamp,
                credentialScope,
                Hash(canonicalRequest));

            /* -- Task 3: Calculate the signature -- */

            byte[] signingKey = getSignatureKey(secretKey, datestamp, region, service);

            string signature = toHexString(HMac(signingKey,
                                         ASCIIEncoding.ASCII.GetBytes(stringToSign)));

            /* -- Task 4: Add signing information to the request -- */

            string authorizationHeader = String.Format(CultureInfo.InvariantCulture, "{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}",
                algorithm, accessKey, credentialScope, signedHeaders, signature);

            return new Tuple<string, string>(authorizationHeader, timestamp);
        }
    }

    /// <summary>
    /// A SCRAM-SHA SASL authenticator.
    /// </summary>
    public class MongoIAMAuthenticator : SaslAuthenticator
    {
        // static properties
        /// <summary>
        /// Gets the name of the mechanism.
        /// </summary>
        /// <value>
        /// The name of the mechanism.
        /// </value>
        public static string MechanismName => "MONGODB-IAM";

        // fields
        private readonly string _databaseName;

        // constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="ScramShaAuthenticator"/> class.
        /// </summary>
        /// <param name="credential">The credential.</param>
        public MongoIAMAuthenticator(UsernamePasswordCredential credential)

            : base(new MongoIAMMechanism(credential, new DefaultRandomStringGenerator()))
        {
            _databaseName = credential.Source;
        }

        // properties
        /// <inheritdoc/>
        public override string DatabaseName => _databaseName;

        // nested classes
        private class MongoIAMMechanism : ISaslMechanism
        {
            private readonly UsernamePasswordCredential _credential;
            private readonly string _name;
            private readonly IRandomStringGenerator _randomStringGenerator;

            public MongoIAMMechanism(
                UsernamePasswordCredential credential,
                IRandomStringGenerator randomStringGenerator)
            {
                _name = "MONGODB-IAM";
                _credential = Ensure.IsNotNull(credential, nameof(credential));
                _randomStringGenerator = Ensure.IsNotNull(randomStringGenerator, nameof(randomStringGenerator));
            }

            public string Name => _name;

            public ISaslStep Initialize(IConnection connection, SaslConversation conversation, ConnectionDescription description)
            {
                Ensure.IsNotNull(connection, nameof(connection));
                Ensure.IsNotNull(description, nameof(description));

                var r = GenerateRandomString();
                var nonce = UTF8Encoding.UTF8.GetBytes(r);
                ClientFirstMessage first = new ClientFirstMessage() { r = nonce, p = 'n' };
                var doc = first.ToBsonDocument();
                var clientFirstMessageBytes = ASCIIEncoding.ASCII.GetBytes(System.Convert.ToBase64String(ToBytes(doc)));

                return new ClientFirst(clientFirstMessageBytes, nonce, _credential);
            }


            private string GenerateRandomString()
            {
                // TODO - we need truly random bytes
                const string legalCharacters = "!\"#$%&'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

                return _randomStringGenerator.Generate(32, legalCharacters);
            }
        }

        private class ClientFirstMessage
        {
            public byte[] r;
            public int p;
        }

        //private class ServerFirstMessage
        //{
        //    public byte[] s;
        //}


        private class ClientSecondMessage
        {
            public string a;
            public string d;
            // TODO
            // string t;
        }

        private static BsonDocument ToDocument(byte[] bytes)
        {
            MemoryStream stream = new MemoryStream(bytes);
            using (var jsonReader = new BsonBinaryReader(stream))
            {
                var context = BsonDeserializationContext.CreateRoot(jsonReader);
                return BsonDocumentSerializer.Instance.Deserialize(context);
            }
        }


        private static byte[] ToBytes(BsonDocument doc)
        {
            BsonBinaryWriterSettings settings = new BsonBinaryWriterSettings()
            {
                // C# driver "magically" changes UUIDs underneath by default so tell it not to
                GuidRepresentation = GuidRepresentation.Standard
            };
            return doc.ToBson(null, settings);
        }

        private class ClientFirst : ISaslStep
        {

            private readonly byte[] _bytesToSendToServer;
            private readonly byte[] _nonce;
            private readonly UsernamePasswordCredential _credential;

            public ClientFirst(
                byte[] bytesToSendToServer,
                byte[] nonce,
                UsernamePasswordCredential credential)
            {
                _bytesToSendToServer = bytesToSendToServer;
                _nonce = nonce;
                _credential = credential;
            }

            public byte[] BytesToSendToServer => _bytesToSendToServer;

            public bool IsComplete => false;

            public ISaslStep Transition(SaslConversation conversation, byte[] bytesReceivedFromServer)
            {
                char[] chars = new char[bytesReceivedFromServer.Length];
                Array.Copy(bytesReceivedFromServer, chars, bytesReceivedFromServer.Length);

                var bytes = System.Convert.FromBase64CharArray(chars, 0, chars.Length);
                var serverFirstMessageDoc = ToDocument(bytes);
                byte[] serverNonce = serverFirstMessageDoc["s"].AsByteArray;

                // TODO - validate serverNonce

                var tuple = AwsSigV4.SignRequest(_credential.Username, _credential.GetInsecurePassword(), null, serverNonce);

                ClientSecondMessage second = new ClientSecondMessage()
                {
                    a = tuple.Item1,
                    d = tuple.Item2,
                };

                var doc = second.ToBsonDocument();
                var clientSecondMessageBytes = ASCIIEncoding.ASCII.GetBytes(System.Convert.ToBase64String(ToBytes(doc)));

                return new ClientLast(clientSecondMessageBytes);
            }
        }

        private class ClientLast : ISaslStep
        {
            private readonly byte[] _bytesToSendToServer;

            public ClientLast(byte[] bytesToSendToServer)
            {
                _bytesToSendToServer = bytesToSendToServer;
            }

            public byte[] BytesToSendToServer => _bytesToSendToServer;

            public bool IsComplete => false;

            public ISaslStep Transition(SaslConversation conversation, byte[] bytesReceivedFromServer)
            {
                return new CompletedStep();
            }
        }
    }
}