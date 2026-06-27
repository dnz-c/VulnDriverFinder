using Microsoft.Deployment.Compression.Cab;
using PeNet;
using Poushec.UpdateCatalogParser;
using Poushec.UpdateCatalogParser.Models;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

static void WriteColor(string message, ConsoleColor color)
{
    var pieces = Regex.Split(message, @"(\[[^\]]*\])");

    for (int i = 0; i < pieces.Length; i++)
    {
        string piece = pieces[i];

        if (piece.StartsWith("[") && piece.EndsWith("]"))
        {
            Console.ForegroundColor = color;
            piece = piece.Substring(1, piece.Length - 2);
        }

        Console.Write(piece);
        Console.ResetColor();
    }

    Console.WriteLine();
}

string[] sus_imports =
{
    "ZwMapViewOfSection",
    "MmMapIoSpace",
    "IoCreateDevice",
    "IofCompleteRequest"
};
void ProcessFile(string path)
{
    var filename = path.Split('\\').Last();
    var extension = path.Split('.').Last();
    if (extension != "sys")
        return;

    var header = new PeFile(path);
    if (header.ImageNtHeaders.FileHeader.Machine != PeNet.Header.Pe.MachineType.Amd64)
        return;
    //Console.WriteLine($"Scanning {path}");

    var imports = header.ImportedFunctions;
    var pot_vuln = false;
    List<string> sus_imported = new List<string>();

    foreach (var import in sus_imports)
    {
        foreach (var p_import in imports)
        {
            if (p_import.Name == import)
            {
                pot_vuln = true;
                sus_imported.Add(p_import.Name);
            }
        }
    }

    if (!pot_vuln)
        return;

    if (!sus_imported.Contains("IoCreateDevice") && !sus_imported.Contains("IofCompleteRequest"))
        return;

    if (!(sus_imported.Contains("MmMapIoSpace") || sus_imported.Contains("ZwMapViewOfSection")))
        return;

    var file = File.ReadAllBytes(path);
    if (file.Length > 100000)
        return;

    Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\check_me");

    WriteColor($"Found potentially vulnerable driver: [{filename}]", ConsoleColor.Green);
    foreach(var sus_imp in sus_imported)
    {
        WriteColor($"    Imports: [{sus_imp}]", ConsoleColor.Red);
    }

    if (!File.Exists(Directory.GetCurrentDirectory() + "\\check_me\\" + header.ImageNtHeaders.FileHeader.TimeDateStamp + "_" + filename))
        File.Copy(path, Directory.GetCurrentDirectory() + "\\check_me\\" + header.ImageNtHeaders.FileHeader.TimeDateStamp + "_" + filename);
}

void ProcessDirectory(string targetDirectory)
{
    // Process the list of files found in the directory.
    string[] fileEntries = Directory.GetFiles(targetDirectory);
    foreach (string fileName in fileEntries)
        ProcessFile(fileName);

    // Recurse into subdirectories of this directory.
    string[] subdirectoryEntries = Directory.GetDirectories(targetDirectory);
    foreach (string subdirectory in subdirectoryEntries)
        ProcessDirectory(subdirectory);
}

var client = new HttpClient();
var catalogClient = new CatalogClient(client, CultureInfo.InvariantCulture, 3);

Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\downloads");

Console.Write("Input search query: ");
var query = Console.ReadLine();

var results = await catalogClient.SendSearchQueryAsync(query);

Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\downloads\\" + query);

Console.WriteLine($"Scanning through {results.Count} items");
    int i = 1;

Parallel.ForEach(results, (item, state, index) =>
{
    Console.WriteLine($"[{index}/{results.Count}] Processing {item.Title} ({item.Size})");

    if (item.Classification.Contains("Driver"))
    {
        var path = Directory.GetCurrentDirectory() + "\\downloads\\" + query + "\\" + item.UpdateID;
        if (Directory.Exists(path) || item.SizeInBytes > 20971524)
        {
            return;
        }
        UpdateInfo update_details;

        try
        {
            update_details = catalogClient.GetUpdateDetailsAsync(item).Result;
        }
        catch
        {
            Console.WriteLine("Fucked up");
            return;
        }

        using (var dl_client = new WebClient())
        {
            dl_client.DownloadFile(update_details.DownloadLinks[0], path + ".cab");

            CabInfo cab = new CabInfo(path + ".cab");
            Directory.CreateDirectory(path);
            cab.Unpack(path);
            File.Delete(path + ".cab");
            ProcessDirectory(path);

            DirectoryInfo di = new DirectoryInfo(path);
            try
            {
                foreach (FileInfo file in di.GetFiles())
                {
                    file.Delete();
                }
                foreach (DirectoryInfo dir in di.GetDirectories())
                {
                    dir.Delete(true);
                }
            }
            catch { }
        }
    }
});

string targetDir = Path.Combine(Directory.GetCurrentDirectory(), "check_me");

Console.Write($"Found {Directory.GetFiles(targetDir).Length} potentiall vulnerable drivers, do you want AI analysis on these drivers? (y/n): ");
string? ai_analysis = Console.ReadLine();

if (Directory.Exists(targetDir) && Directory.GetFiles(targetDir).Length > 0 && ai_analysis == "y")
{
    Console.WriteLine("\nstarting Claude analysis of potentially vulnerable drivers");

    string prompt = """
        Your task is to create a complete and comprehensive reverse engineering analysis.
        The Task is to determine wether this driver exposes physical read/write privileges to a usermode application via IOCTL.
        If it exposes such a vulnerability write a small PoC of a usermode process that sends commands to the driver to read/write physical memory

        Use the following systematic methodology:

        1. **Decompilation Analysis**
           - Thoroughly inspect the decompiler output
           - Add detailed comments documenting your findings
           - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

        2. **Improve Readability in the Database**
           - Rename variables to sensible, descriptive names
           - Correct variable and argument types where necessary (especially pointers and array types)
           - Update function names to be descriptive of their actual purpose

        3. **Deep Dive When Needed**
           - If more details are necessary, examine the disassembly and add comments with findings
           - Document any low-level behaviors that aren't clear from the decompilation alone
           - Use sub-agents to perform detailed analysis

        4. **Important Constraints**
           - NEVER convert number bases yourself - use the int_convert MCP tool if needed
           - Use MCP tools to retrieve information as necessary
           - Derive all conclusions from actual analysis, not assumptions

        5. **Documentation**
           - Produce comprehensive RE/*.md files with your findings
           - Document the steps taken and methodology used
           - When asked by the user, ensure accuracy over previous analysis file
           - Organize findings in a way that serves the project goals outlined in in this prompt.
        """;

    var claudeProcess = new ProcessStartInfo
    {
        FileName = "claude",
        Arguments = "--print --dangerously-skip-permissions --model opusplan --allowedTools Read,Write,Bash,mcp__plugin_ida-pro_idalib__*",
        WorkingDirectory = targetDir,
        UseShellExecute = false,
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
    };

    try
    {
        using var proc = Process.Start(claudeProcess)!;
        await proc.StandardInput.WriteLineAsync(prompt);
        proc.StandardInput.Close();

        using var cts = new CancellationTokenSource();
        char[] spinner = { '|', '/', '-', '\\' };

        var spinnerTask = Task.Run(async () =>
        {
            int frame = 0;
            try
            {
                while (true)
                {
                    Console.Write($"\r  Analyzing... {spinner[frame++ % 4]}");
                    await Task.Delay(100, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            Console.Write("\r" + new string(' ', 25) + "\r");
        });

        string? line;
        while ((line = await proc.StandardOutput.ReadLineAsync()) != null)
        {
            if (!cts.IsCancellationRequested)
            {
                cts.Cancel();
                await spinnerTask;
            }
            Console.WriteLine(line);
        }

        cts.Cancel();
        await spinnerTask;
        proc.WaitForExit();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"could not invoke claude code: {ex.Message}");
    }
}
else
{
    Console.WriteLine("\nno potentially vulnerable drivers were found to analyze or no analysis was requested");
}

Console.WriteLine("done.");
Console.ReadKey();
