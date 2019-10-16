/* Copyright 2010-present MongoDB Inc.
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
using System.IO;
using MongoDB.Bson;
using MongoDB.Driver.Core.Configuration;
using MongoDB.Driver.Core.Events.Diagnostics;

namespace MongoDB.Driver.TestConsoleApplication
{
    class Program
    {
        static void Main(string[] args)
        {
            ////FilterMeasuring.TestAsync().GetAwaiter().GetResult();
            //int numConcurrentWorkers = 50;
            ////new CoreApi().Run(numConcurrentWorkers, ConfigureCluster);
            //new CoreApiSync().Run(numConcurrentWorkers, ConfigureCluster);

            //new Api().Run(numConcurrentWorkers, ConfigureCluster);

            ////new LegacyApi().Run(numConcurrentWorkers, ConfigureCluster);.
            ///
            MongoClientSettings settings = new MongoClientSettings();
            //settings.UseTls = true;
            settings.Server = new MongoServerAddress("10.1.2.19", 27017);
            settings.Credential = new MongoCredential("MONGODB-IAM", 
                new MongoExternalIdentity(
                    Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")), 
                    new PasswordEvidence(Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY"))
                );
            var client = new MongoClient(settings);

            var db = client.GetDatabase("foo");
            var collection = db.GetCollection<BsonDocument>("bar");

            Console.WriteLine("Count: " + collection.FindSync(new BsonDocumentFilterDefinition<BsonDocument>(new BsonDocument()) ).ToList().ToArray().Length);

            Console.WriteLine("Done...");
        }

        private static void ConfigureCluster(ClusterBuilder cb)
        {
#if NET452
            cb.UsePerformanceCounters("test", true);
#endif
        }
    }
}