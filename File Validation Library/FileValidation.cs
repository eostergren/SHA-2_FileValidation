using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Validate_Files_Library
{

public class FileValidation
{

    #region Constructors

    public FileValidation() : this(System.Environment.CurrentDirectory)
    {
    }

    public FileValidation(string SearchPath)
    {
        m_SearchPathRoot = SearchPath;
        m_DirInfo = new DirectoryInfo(m_SearchPathRoot);
    }

    #endregion Constructors

    #region Public Methods

    public void Generate(List<string> FileExtensions)
    {
        TotalFileCount = 0;
        TotalDirectoryCount = 0;
        List<string> OutputMessages = new List<string>();
        string header = ("Generate SHA2 using :");
        foreach(string ext in FileExtensions)
        {
            header += " " + ext + " ";
        }
        OutputMessages.Add(header);
        CreateOutputFile(OutputMessages);
        AppendOutputFile(GenerateRecursive(FileExtensions));
        OutputMessages.Clear();
        string summary = end_line + String.Format("{0:d} Directories found, {1:d} Files processed", TotalDirectoryCount, TotalFileCount);
        OutputMessages.Add(summary);
        Console.WriteLine(summary);
        AppendOutputFile(OutputMessages);
    }

    public void Verify(List<string> FileExtensions)
    {
        TotalFileCount = 0;
        TotalDirectoryCount = 0;
        List<string> OutputMessages = new List<string>();
        string header = ("Validate SHA2 using :");
        foreach (string ext in FileExtensions)
        {
            header += " " + ext + " ";
        }
        OutputMessages.Add(header);
        CreateOutputFile(OutputMessages);
        AppendOutputFile(RecursiveVerify(FileExtensions));
        string summary = end_line + String.Format("{0:d} Directories found, {1:d} Files processed", TotalDirectoryCount, TotalFileCount);
        OutputMessages.Clear();
        OutputMessages.Add(summary);
        Console.WriteLine(summary);
        AppendOutputFile(OutputMessages);
    }

    public void Compare(string[] FilePath)
    {
        TotalFileCount = 0;
        TotalDirectoryCount = 0;
        List<string> OutputMessages = new List<string>();
        string header = "Compare SHA-2 in " + FilePath[1] + " and " + FilePath[2];
        OutputMessages.Add(header);
        CreateOutputFile(OutputMessages);
        AppendOutputFile(RecursiveCompare(FilePath));
        OutputMessages.Clear();
        string summary = end_line + string.Format("{0:d} Directories found, {1:d} SHA-2 records compared", TotalDirectoryCount, TotalFileCount);
        OutputMessages.Add(summary);
        Console.WriteLine(summary);
        AppendOutputFile(OutputMessages);
    }

    #endregion Public Methods

    #region Private Methods

    private List<string> GenerateRecursive(List<string> FileExtensions)
    {
        List<string> SHA2Errors = new List<string>();
        try
        {
            if (File.Exists(SHA2_filename))
            {
                // TODO - may add support to add new types later on
                FileAttributes curAttributes = File.GetAttributes(SHA2_filename);
                File.SetAttributes(SHA2_filename, curAttributes & ~FileAttributes.ReadOnly);
            }
            int FileCountInFolder = 0;
            foreach (string Extension in FileExtensions)
            {
                IEnumerable<FileInfo> Files = m_DirInfo.EnumerateFiles("*." + Extension);
                FileCountInFolder += Files.Count();
            }
            // test if we need to create a SHA-2 record file in this folder
            if (FileCountInFolder > 0)
            {
                SHA256Cng ShaHashGenerator = new SHA256Cng();
                byte[] hashValue;
                Console.WriteLine(end_line + "Generate SHA2 for {0:d} files found in " + m_SearchPathRoot, FileCountInFolder);
                using (StreamWriter OutFile = File.CreateText(SHA2_filename))
                {
                    OutFile.WriteLine(m_DirInfo.FullName + "    " + DateTime.Now.ToLocalTime().ToString() + end_line);
                    foreach (string Extension in FileExtensions)
                    {
                        IEnumerable<FileInfo> Files = m_DirInfo.EnumerateFiles("*." + Extension);
                        if (Files.Count() > 0)
                        {
                            foreach (FileInfo fInfo in Files)
                            {
                                using (FileStream InFile = File.OpenRead(fInfo.FullName))
                                {
                                    InFile.Position = 0;
                                    hashValue = ShaHashGenerator.ComputeHash(InFile);
                                    string LineRecord = ByteArrayToString(hashValue) + delimiter + fInfo.Name;
                                    OutFile.WriteLine(LineRecord);
                                    // Console.WriteLine(LineRecord);
                                    ++TotalFileCount;
                                }
                                FileAttributes curAttributes = File.GetAttributes(fInfo.FullName);
                                File.SetAttributes(fInfo.FullName, curAttributes | FileAttributes.ReadOnly);
                            }
                        }
                    }
                    if (File.Exists(SHA2_filename))
                    {
                        FileAttributes curAttributes = File.GetAttributes(SHA2_filename);
                        File.SetAttributes(SHA2_filename, curAttributes | FileAttributes.ReadOnly);
                    }
                }
            }
            if (m_DirInfo.Exists)
            {
                ++TotalDirectoryCount;
                IEnumerable<DirectoryInfo> Directories = m_DirInfo.EnumerateDirectories();
                foreach (DirectoryInfo SubDir in Directories)
                {
                    FileValidation SubSearch = new FileValidation(SubDir.FullName);
                    AppendOutputFile(SubSearch.GenerateRecursive(FileExtensions));
                }
            }
        }
        catch(Exception e)
        {
            // does the user have permissions to access this directory ?
            SHA2Errors.Add(m_DirInfo.FullName);
            SHA2Errors.Add( e.Message);
            Console.WriteLine(e.Message);
        }
        return SHA2Errors;
    }

    private List<string> RecursiveVerify(List<string> FileExtensions)
    {
        List<string> FileErrors = new List<string>();
        try
        {
            SHA256Cng SHA2HashGenerator = new SHA256Cng();
            List<string> FileList = BuildSHA2List(SHA2_filename);

            foreach (string Extension in FileExtensions)
            {
                // process only those files we care about
                string FileMatch = "*." + Extension;
                IEnumerable<FileInfo> Files = m_DirInfo.EnumerateFiles(FileMatch);
                if (Files.Count() > 0)
                {
                    Console.WriteLine(end_line + "validating SHA256 for " + m_SearchPathRoot);
                    byte[] hashValue;

                    List<string> FoundFiles = new List<string>();
                    foreach (FileInfo fInfo in Files)
                    {
                        // make sure this is in the list of protected files
                        bool found = false;
                        foreach (string FileRecord in FileList)
                        {
                            int offset = FileRecord.Length - NameOffset;
                            if (offset > 0)
                            {
                                char[] buffer = new char[FileRecord.Length - NameOffset];
                                FileRecord.CopyTo(NameOffset, buffer, 0, FileRecord.Length - NameOffset);
                                string FileNameInRecord = new string(buffer);
                                if (FileNameInRecord.Equals(fInfo.Name))
                                {
                                    found = true;
                                    ++TotalFileCount;
                                    FoundFiles.Add(FileRecord);
                                    using (FileStream InFile = File.OpenRead(fInfo.FullName))
                                    {
                                        InFile.Position = 0;
                                        hashValue = SHA2HashGenerator.ComputeHash(InFile);
                                    }
                                    if (!FileRecord.Contains(ByteArrayToString(hashValue)))
                                    {
                                        string error_message = fInfo.FullName + " Calculated SHA2: " + end_line +  ByteArrayToString(hashValue) + end_line + FileRecord;
                                        FileErrors.Add(error_message);
                                        Console.Write("SHA-2 Error found in " + fInfo.FullName + end_line);
                                    }
                                }
                            }
                        }
                        if (!found)
                        {
                            string error_message = fInfo.Name + " not found in record file: " + SHA2_filename;
                            FileErrors.Add(error_message);
                            Console.WriteLine(error_message);
                        }
                    }
                    foreach(string FileRecord in FileList)
                    {
                        if (!FoundFiles.Contains(FileRecord))
                        {
                            string error_message = FileRecord + " missing from directory: " + m_SearchPathRoot;
                            FileErrors.Add(error_message);
                            Console.Write(error_message);

                        }
                    }
                }
            }
            if (m_DirInfo.Exists)
            {
                ++TotalDirectoryCount;
                IEnumerable<DirectoryInfo> Directories = m_DirInfo.EnumerateDirectories();
                foreach (DirectoryInfo SubDir in Directories)
                {
                    FileValidation SubSearch = new FileValidation(SubDir.FullName);
                    AppendOutputFile(SubSearch.RecursiveVerify(FileExtensions));
                }
            }
        }
        catch (Exception e)
        {
            // does the user have permissions to access this directory ?
            FileErrors.Add(m_DirInfo.FullName);
            FileErrors.Add(e.Message);
            Console.WriteLine(e.Message);
        }
        return FileErrors;
    }

    private List<string> RecursiveCompare(string[] FilePath)
    {
        List<string> CompareErrors = new List<string>();
        try
        {
            // expecting an identical directory tree for the alternate copy
            string SHA2_alt_filename = SHA2_filename.Replace(FilePath[1], FilePath[2]);
            if (File.Exists(SHA2_filename))
            {
                if (File.Exists(SHA2_alt_filename))
                {
                    List<string> FileList = BuildSHA2List(SHA2_filename);
                    List<string> Alt_FileList = BuildSHA2List(SHA2_alt_filename);
                    // make sure this is in the list of protected files

                    List<string> MatchedFiles = new List<string>();
                    foreach (string FileRecord in FileList)
                    {
                        int offset = FileRecord.Length - NameOffset;
                        if (offset > 0)
                        {
                            char[] buffer = new char[FileRecord.Length - NameOffset];
                            FileRecord.CopyTo(NameOffset, buffer, 0, FileRecord.Length - NameOffset);
                            string FileNameInRecord = new string(buffer);

                            bool found = false;
                            foreach (string Alt_FileRecord in Alt_FileList)
                            {
                                char[] alt_buffer = new char[Alt_FileRecord.Length - NameOffset];
                                Alt_FileRecord.CopyTo(NameOffset, alt_buffer, 0, Alt_FileRecord.Length - NameOffset);
                                string Alt_FileNameInRecord = new string(alt_buffer);
                                if (Alt_FileNameInRecord.Equals(FileNameInRecord))
                                {
                                    found = true;
                                    ++TotalFileCount;
                                    MatchedFiles.Add(Alt_FileRecord);
                                    if (!Alt_FileRecord.Equals(FileRecord))
                                    {
                                        string errormsg = "SHA2 mismatch found in: " + m_SearchPathRoot + end_line + FileRecord + end_line + Alt_FileRecord + end_line;
                                        CompareErrors.Add(errormsg);
                                        Console.WriteLine(errormsg);
                                    }
                                        break;
                                }
                            }
                            if (!found)
                            {
                                string error_message = FileNameInRecord + " not found in " + SHA2_alt_filename + end_line;
                                CompareErrors.Add(error_message);
                                Console.WriteLine(error_message);
                            }
                        }
                    }
                    foreach (string Alt_FileRecord in Alt_FileList)
                    {
                        if (!MatchedFiles.Contains(Alt_FileRecord))
                        {
                            char[] buffer = new char[Alt_FileRecord.Length - NameOffset];
                            Alt_FileRecord.CopyTo(NameOffset, buffer, 0, Alt_FileRecord.Length - NameOffset);
                            string FileNameInRecord = new string(buffer);
                            string error_message = FileNameInRecord + " not found in " + SHA2_filename + end_line;
                            CompareErrors.Add(error_message);
                            Console.WriteLine(error_message);
                        }
                    }
                }
                else
                {
                    string errmsg = "validation file not found: " + SHA2_alt_filename + end_line;
                    CompareErrors.Add(errmsg);
                    Console.WriteLine(errmsg);
                }
            }
            else if (File.Exists(SHA2_alt_filename))
            {
                string errmsg = "validation file not found: " + SHA2_filename + end_line;
                CompareErrors.Add(errmsg);
                Console.WriteLine(errmsg);
            }
            if (m_DirInfo.Exists)
            {
                ++TotalDirectoryCount;
                IEnumerable<DirectoryInfo> Directories = m_DirInfo.EnumerateDirectories();
                foreach (DirectoryInfo SubDir in Directories)
                {
                    FileValidation SubSearch = new FileValidation(SubDir.FullName);
                    AppendOutputFile(SubSearch.RecursiveCompare(FilePath));
                }
            }
        }
        catch (Exception e)
        {
            // does the user have permissions to access this directory ?
            CompareErrors.Add(m_DirInfo.FullName);
            CompareErrors.Add(e.Message);
            Console.WriteLine(e.Message);
        }
        return CompareErrors;
    }

    private List<string> BuildSHA2List(string filename)
    {
        List<string> FileList = new List<string>();
        // get all files that are protected by a SHA2 in the record file
        if (File.Exists(filename))
        {
            using (StreamReader sr = File.OpenText(filename))
            {
                string s = "";
                while ((s = sr.ReadLine()) != null)
                {
                    if (!s.Contains(":") && (s.Length > delimiter.Length + SHA2_length))
                    {
                        FileList.Add(s);
                    }
                }
            }
        }
        return FileList;
    }

    private void CreateOutputFile(List<string> FileErrors)
    {
        using (StreamWriter sw = File.CreateText(SHA2_ErrorReportFileName))
        {
            DateTime localDate = DateTime.Now;
            sw.WriteLine(m_DirInfo.FullName + "    " + DateTime.Now.ToLocalTime().ToString() + end_line);
            if (FileErrors.Count > 0)
            {
                foreach (string err in FileErrors)
                {
                    sw.WriteLine(err);
                }
            }
        }
    }

    private void AppendOutputFile(List<string> FileErrors)
    {
        using (StreamWriter sw = File.AppendText(SHA2_ErrorReportFileName))
        {
            if (FileErrors.Count > 0)
            {
                foreach (string err in FileErrors)
                {
                    sw.WriteLine(err);
                }
            }
        }
    }

    private string ByteArrayToString(byte[] array)
    {
        string str = "";
        int i;
        for (i = 0; i < array.Length; i++)
        {
            str += (String.Format("{0:X2}", array[i]));
        }
        return str;
    }

    #endregion Private Methods

    #region Private Properties

    private string SHA2_filename
    {
        get
        {
            string path = m_SearchPathRoot + @"\SHA2_" + m_DirInfo.Name + ".txt";
            //if (path.Length > max_filename_length)
            //{ this would will break if content is moved to a shorter path...
            //    path = m_SearchPathRoot + @"\SHA2_use_a_short_name.txt"; ?
            //}
            return path;
        }
    }

    private string SHA2_ErrorReportFileName
    {
        get
        {
            if (File.Exists(SHA2_ErrorReport))
            {
                FileAttributes curAttributes = File.GetAttributes(SHA2_ErrorReport);
                File.SetAttributes(SHA2_ErrorReport, curAttributes & ~FileAttributes.ReadOnly);
            }
            return SHA2_ErrorReport;
        }
    }

    private int NameOffset
    {
        get
        {
            return SHA2_length + delimiter.Length;
        }
    }

    private int TotalFileCount
    {
        set
        {
            sm_TotalFileCount = value;
        }
        get
        {
            return sm_TotalFileCount;
        }
    }

    private int TotalDirectoryCount
    {
        set
        {
            sm_TotalDirectoryCount = value;
        }
        get
        {
            return sm_TotalDirectoryCount;
        }
    }

    #endregion Private Properties

    #region Member Data

    static private int sm_TotalFileCount;
    static private int sm_TotalDirectoryCount;
    private string m_SearchPathRoot;
    private DirectoryInfo m_DirInfo;
    private const string SHA2_ErrorReport = "SHA2_ErrorReport.txt";
    private const string delimiter = "  ...  ";
    private const string end_line = "\r\n";
    private const int SHA2_length = 64;

    #endregion Member Data
}

}
