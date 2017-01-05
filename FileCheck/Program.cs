using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;

using Validate_Files_Library;


namespace FileCheck
{
class Program
{
    static void Main(string[] args)
    {
        //    Console.ForegroundColor = ConsoleColor.Cyan;
        bool show_help = true;

        if (args.Length > 1)
        {
            List<string> arglist = new List<string>();
            for (int i = 1; i < args.Length; i++)
            {
                arglist.Add(args[i]);
            }

            if (args[0].Equals("-generate"))
            {
                FileValidation FileTest = new FileValidation();
                FileTest.Generate(arglist);
                show_help = false;
            }
            else if (args[0].Equals("-validate"))
            {
                FileValidation FileTest = new FileValidation();
                FileTest.Verify(arglist);
                show_help = false;
            }
            else if ((args[0].Equals("-compare")) && (args.Length > 2))
            {
                FileValidation FileTest = new FileValidation(args[1]);
                FileTest.Compare(args);
                show_help = false;
            }
        }

        if (show_help)
        {
            string codeBase = Assembly.GetExecutingAssembly().CodeBase;
            string executable = Path.GetFileName(codeBase);
            string name = executable.ToLower().Replace(".exe", " "); ;
            Console.WriteLine("To create or verify SHA-2 values starting from the working directory:");
            Console.WriteLine(name + "[ -generate | -validate ] <extension 1> <extension 2> ... <extension n>\r\n");
            // -compare is useful only when the -generate option is run against two copies of the same data
            // to determine if one set is corrupted before SHA-2 generation...
            Console.WriteLine("To compare SHA-2 record files for two file sets:");
            Console.WriteLine(name + "-compare <path 1> <path 2>");
        }
    }
}
}
