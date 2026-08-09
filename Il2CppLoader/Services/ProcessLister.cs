using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Il2CppLoader.Services;

public sealed record ProcessItem(int Pid, string Name, string Path, string Kind);

/// <summary>
/// Cross-platform process enumeration. On Linux, resolves exe paths through
/// /proc and handles Wine-hosted Windows processes, whose /proc/pid/exe points
/// to wine-preloader — the real game path is recovered from the cmdline
/// (relative, "Z:\..." and mixed-slash forms are all normalized).
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
                var item = Inspect(p);
                if (item != null)
                    result.Add(item);
            }
            catch { }
            finally { p.Dispose(); }
        }
        result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    private static ProcessItem? Inspect(Process p)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            string path;
            try { path = p.MainModule?.FileName ?? ""; }
            catch { return null; }
            if (string.IsNullOrEmpty(path))
                return null;
            return new ProcessItem(p.Id, p.ProcessName, path, "WIN");
        }

        string exeLink;
        try
        {
            var target = new FileInfo($"/proc/{p.Id}/exe").ResolveLinkTarget(true);
            exeLink = target?.FullName ?? "";
        }
        catch { exeLink = ""; }

        string cmdline = "";
        try { cmdline = File.ReadAllText($"/proc/{p.Id}/cmdline"); } catch { }

        bool isWine = exeLink.Contains("wine", StringComparison.OrdinalIgnoreCase);

        if (isWine)
        {
            // recover the windows executable from the cmdline
            string? gamePath = ResolveWineExe(p.Id, cmdline);
            if (gamePath == null)
                return null;
            return new ProcessItem(p.Id, System.IO.Path.GetFileNameWithoutExtension(gamePath), gamePath, "WINE");
        }

        if (!string.IsNullOrEmpty(exeLink))
            return new ProcessItem(p.Id, p.ProcessName, exeLink, "LNX");

        // fallback: first cmdline token
        if (cmdline.Length > 0)
        {
            string first = cmdline.Split('\0')[0];
            if (!string.IsNullOrEmpty(first))
                return new ProcessItem(p.Id, p.ProcessName, first, "LNX");
        }
        return null;
    }

    /// <summary>
    /// Extracts the game .exe path from a wine process cmdline and maps it to
    /// a Linux path. Handles "VRisingServer.exe" (relative to the process cwd),
    /// "Z:\home\...\Game.exe", "Z:/home/...\Game.exe" and plain linux paths.
    /// Returns null for wine-internal programs (C:\windows\...).
    /// </summary>
    private static string? ResolveWineExe(int pid, string cmdline)
    {
        if (cmdline.Length == 0)
            return null;
        var tokens = cmdline.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
            return null;

        string first = tokens[0].Trim('"');
        if (!first.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return null;

        // Z:\... or Z:/... -> the linux filesystem root mapping
        if (first.Length > 2 && char.ToUpperInvariant(first[0]) == 'Z' && first[1] == ':')
        {
            string mapped = first[2..].Replace('\\', '/');
            if (!mapped.StartsWith('/'))
                mapped = "/" + mapped;
            return File.Exists(mapped) ? mapped : null;
        }

        // other drive letters (C:\...) live inside the wine prefix — not a game path
        if (first.Length > 2 && char.IsLetter(first[0]) && first[1] == ':')
            return null;

        // already a linux path
        if (first.StartsWith('/'))
            return File.Exists(first) ? first : null;

        // relative -> resolve against the process working directory
        try
        {
            var cwd = new FileInfo($"/proc/{pid}/cwd").ResolveLinkTarget(true)?.FullName;
            if (cwd != null)
            {
                string combined = System.IO.Path.GetFullPath(Path.Combine(cwd, first));
                if (File.Exists(combined))
                    return combined;
            }
        }
        catch { }
        return null;
    }
}
