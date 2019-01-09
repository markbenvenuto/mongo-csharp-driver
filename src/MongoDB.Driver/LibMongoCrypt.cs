using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace MongoDB.Driver
{
    /*
     * Windows:
     * https://stackoverflow.com/questions/2864673/specify-the-search-path-for-dllimport-in-net
     * 
     * See for better ways
     * https://github.com/dotnet/coreclr/issues/930
     * https://github.com/dotnet/corefx/issues/32015
     * 
     */
    internal class LibMongoCrypt
    {

#if !FOOO
        static LibMongoCrypt()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                SetWinDllDirectory();
            }
            else 
            {
                LoadLinux();
            }
            //if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        }



        private static void SetWinDllDirectory()
        {
            // PS - I hate .net standard 1.5,
            // TODO We should use GetExecutingAssembly here
            var location = Assembly.GetEntryAssembly().Location;
            string path = Path.GetDirectoryName(location);

            // Nuget package
            // TODO - handle packages for .nuget

            var platform = IntPtr.Size == 8 ? @"D:\mongo-c-driver\src\libbson\Debug\" : "x86";
            if (!SetDllDirectoryW(Path.Combine(path, platform)))
            {
                throw new NotImplementedException("bad");
            }
        }

        private static LoadLinux()
        {
            dlopen("");
        }

        [DllImport("libdl")]
        private static extern IntPtr dlopen(string filename, int flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetDllDirectoryW(string path);


        private const string DllName = "libbson-1.0.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet =CharSet.Ansi)]
        private static extern System.IntPtr bson_get_version();


        public static string GetBsonVersion()
        {
            IntPtr p = bson_get_version();
            return Marshal.PtrToStringAnsi(p);
            //return "hi2";
        }
#else
        public static string GetBsonVersion()
        {
            return "hi3";
        }

#endif
    }
}
