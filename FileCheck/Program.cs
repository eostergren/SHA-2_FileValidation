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
        if (args.Length > 1)
        {
            FileValidation FileTest = new FileValidation();
            string[] cmd_vals = new string[args.Length - 1];
            System.Array.Copy(args, 1, cmd_vals, 0, cmd_vals.Length);
            switch (args[0])
            {
                case "-generate":
                    FileTest.run(cmd_vals, FileValidation.Action.generate);
                    break;
                case "-validate":
                    FileTest.run(cmd_vals, FileValidation.Action.validate);
                    break;
                case "-compare":
                    FileTest.run(cmd_vals, FileValidation.Action.compare);
                    break;
                default:
                    show_help();
                    break;
            }
        }
    }

    static private void show_help()
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
