using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Il2CppLoader.Services;

public enum GamePlatform { Unknown, Windows, LinuxNative }
public enum ScriptingBackend { Unknown, Il2Cpp, Mono }

public sealed record GameInfo(
    string ExePath,
    string GameDir,
    string? DataDir,
    GamePlatform Platform,
    ScriptingBackend Backend,
    string UnityVersion,
    int MetadataVersion,
    bool RunningUnderWine)
{
    public string BackendName => Backend switch
    {
        ScriptingBackend.Il2Cpp => "IL2CPP",
        ScriptingBackend.Mono => "Mono",
        _ => "unknown",
    };

    public string PlatformName => Platform switch
    {
        GamePlatform.Windows => RunningUnderWine ? "Windows (Wine)" : "Windows",
        GamePlatform.LinuxNative => "Linux (native)",
        _ => "unknown",
    };

    public string DumpPath => Path.Combine(GameDir, "il2cpp_classes.json");
    public string StringsPath => Path.Combine(GameDir, "il2cpp_strings.json");
    public string LogPath => Path.Combine(GameDir, "il2cpp_dumper.log");
}

/// <summary>
/// Auto-detects everything we need to know about a Unity game from its
/// executable or folder: platform, scripting backend, Unity version and the
/// il2cpp metadata version.
/// </summary>
public static class GameDetector
{
    private static readonly Regex UnityVersionRegex =
        new(@"(?<![\d.])(?:20\d{2}|\d{1,2})\.\d{1,2}\.\d{1,2}[abfp]?\d{0,2}(?![\d.])", RegexOptions.Compiled);

    public static GameInfo FromExecutable(string exePath, bool runningUnderWine = false)
    {
        string gameDir = Path.GetDirectoryName(exePath) ?? ".";
        string? dataDir = FindDataDir(gameDir, exePath);
        var platform = DetectPlatform(exePath);
        var backend = DetectBackend(gameDir, dataDir);
        string unityVersion = dataDir != null ? DetectUnityVersion(dataDir) : "";
        int metadataVersion = dataDir != null ? DetectMetadataVersion(dataDir) : 0;

        return new GameInfo(exePath, gameDir, dataDir, platform, backend,
            unityVersion, metadataVersion, runningUnderWine);
    }

    public static string? FindDataDir(string gameDir, string exePath)
    {
        // <Game>.exe / <Game>.x86_64 -> <Game>_Data
        string baseName = Path.GetFileNameWithoutExtension(exePath);
        string candidate = Path.Combine(gameDir, baseName + "_Data");
        if (Directory.Exists(candidate))
            return candidate;
        // fallback: any *_Data folder
        foreach (var dir in Directory.GetDirectories(gameDir, "*_Data"))
            return dir;
        return null;
    }

    public static GamePlatform DetectPlatform(string exePath)
    {
        try
        {
            using var fs = File.OpenRead(exePath);
            Span<byte> magic = stackalloc byte[4];
            if (fs.Read(magic) < 4)
                return GamePlatform.Unknown;
            if (magic[0] == (byte)'M' && magic[1] == (byte)'Z')
                return GamePlatform.Windows;
            if (magic[0] == 0x7F && magic[1] == (byte)'E' && magic[2] == (byte)'L' && magic[3] == (byte)'F')
                return GamePlatform.LinuxNative;
        }
        catch { }
        return exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? GamePlatform.Windows
            : GamePlatform.Unknown;
    }

    public static ScriptingBackend DetectBackend(string gameDir, string? dataDir)
    {
        if (File.Exists(Path.Combine(gameDir, "GameAssembly.dll")) ||
            File.Exists(Path.Combine(gameDir, "GameAssembly.so")))
            return ScriptingBackend.Il2Cpp;
        if (dataDir != null)
        {
            if (File.Exists(Path.Combine(dataDir, "il2cpp_data", "Metadata", "global-metadata.dat")))
                return ScriptingBackend.Il2Cpp;
            if (Directory.Exists(Path.Combine(dataDir, "Managed")) ||
                Directory.Exists(Path.Combine(dataDir, "MonoBleedingEdge")))
                return ScriptingBackend.Mono;
            // GameAssembly inside Plugins (linux)
            if (File.Exists(Path.Combine(dataDir, "Plugins", "x86_64", "GameAssembly.so")) ||
                File.Exists(Path.Combine(dataDir, "Plugins", "GameAssembly.so")))
                return ScriptingBackend.Il2Cpp;
        }
        return ScriptingBackend.Unknown;
    }

    public static string DetectUnityVersion(string dataDir)
    {
        foreach (var name in new[] { "globalgamemanagers", "mainData" })
        {
            string path = Path.Combine(dataDir, name);
            if (!File.Exists(path))
                continue;
            try
            {
                using var fs = File.OpenRead(path);
                var buf = new byte[Math.Min(fs.Length, 4096)];
                int read = fs.Read(buf, 0, buf.Length);
                // the unity version string sits near the start of the header
                string ascii = Encoding.ASCII.GetString(buf, 0, read);
                var m = UnityVersionRegex.Match(ascii);
                if (m.Success)
                    return m.Value;
            }
            catch { }
        }
        return "";
    }

    public static int DetectMetadataVersion(string dataDir)
    {
        string path = Path.Combine(dataDir, "il2cpp_data", "Metadata", "global-metadata.dat");
        if (!File.Exists(path))
            return 0;
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> hdr = stackalloc byte[8];
            if (fs.Read(hdr) < 8)
                return 0;
            uint magic = BitConverter.ToUInt32(hdr);
            if (magic != 0xFAB11BAF)
                return 0;
            return BitConverter.ToInt32(hdr[4..]);
        }
        catch
        {
            return 0;
        }
    }
}
