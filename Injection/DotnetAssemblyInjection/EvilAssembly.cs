/*
 * Title: Evil Assembly
 * Notes:
 *  - After building it, use bin/Release/EvilAssembly.exe for injecting.
 * Resources:
 *  - https://www.ired.team/offensive-security/code-injection-process-injection/injecting-and-executing-.net-assemblies-to-unmanaged-process
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EvilAssembly
{
    class Program
    {
        static void Main(string[] args)
        {
            return;
        }

        // This method is called by Injector.exe.
        static int evilMethod(String pwzArgument)
        {
            Console.WriteLine("Hi from CLR");
            return 1;
        }
    }
}
