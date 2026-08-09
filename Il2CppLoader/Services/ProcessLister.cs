using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Il2CppLoader.Services;

public sealed record ProcessItem(int Pid, string Name, string Path, string Kind);

/// <summary>
/// Cross-platform process enumeration. On Linux, resolves exe paths through
/// /proc and tags Wine-hosted Windows processes.
/// </summary>
public static class ProcessLister
{
    public static List<ProcessItem> List()
    {
        var result = new List<ProcessItem>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string path = GetExePath(p);
                if (string.IsNullOrEmpty(path))
                    continue;
                string kind = Classify(p, path);
                result.Add(new ProcessItem(p.Id, p.ProcessName, path, kind));
            }
            catch { }
            finally { p.Dispose(); }
        }
        result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    private static string GetExePath(Process p)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            try
            {
                var link = $"/proc/{p.Id}/exe";
                var target = new FileInfo(link).ResolveLinkTarget(true);
                if (target != null)
                    return target.FullName;
            }
            catch { }
            // wine processes: read cmdline
            try
            {
                var cmd = File.ReadAllText($"/proc/{p.Id}/cmdline").Replace('\0', ' ').Trim();
                return cmd.Split(' ')[0];
            }
            catch { }
            return "";
        }
        try
        {
            return p.MainModule?.FileName ?? "";
        }
        catch { }
        return "";
    }

    private static string Classify(Process p, string path)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return "WIN";
        if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return "WINE";
        try
        {
            var cmd = File.ReadAllText($"/proc/{p.Id}/cmdline");
            if (cmd.Contains("wine", StringComparison.OrdinalIgnoreCase) ||
                cmd.Contains(".exe", StringComparison.OrdinalIgnoreCase))
                return "WINE";
        }
        catch { }
        return "LNX";
    }
}
