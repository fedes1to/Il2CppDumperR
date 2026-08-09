using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Il2CppLoader.Services;

public enum InjectMethod
{
    WindowsRemoteThread, // windows host -> windows game
    WineHelper,          // linux host   -> windows game under wine (injector.exe)
    LinuxGdb,            // linux host   -> native linux game (attach + dlopen)
    LinuxPreload,        // linux host   -> native linux game (launch with LD_PRELOAD)
}

public static class InjectionService
{
    // -----------------------------------------------------------------
    // dumper library discovery
    // -----------------------------------------------------------------

    public static string? FindDumperLibrary(GamePlatform platform, string? overridePath = null)
    {
        if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath))
            return overridePath;

        string fileName = platform == GamePlatform.LinuxNative
            ? "libIl2cppDumperR.so"
            : "Il2cppDumperR.dll";

        string baseDir = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDir, fileName),
            Path.Combine(baseDir, "runtimes", fileName),
            // dev layout: loader runs from Il2CppLoader/bin/..., builds in <repo>/build
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "build",
                platform == GamePlatform.LinuxNative ? "linux" : "mingw", fileName)),
        };
        foreach (var c in candidates)
            if (File.Exists(c))
                return c;
        return null;
    }

    public static string? FindWineInjector()
    {
        string baseDir = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDir, "injector.exe"),
            Path.Combine(baseDir, "runtimes", "injector.exe"),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "build", "mingw", "injector.exe")),
        };
        foreach (var c in candidates)
            if (File.Exists(c))
                return c;
        return null;
    }

    // -----------------------------------------------------------------
    // injection
    // -----------------------------------------------------------------

    /// <summary>
    /// Writes il2cpp_dump_dir.txt next to the dumper library. The dumper reads
    /// this file on init (it's in its own module dir, so it works for
    /// Windows/Wine/Linux injection alike) and writes the dumps there.
    /// </summary>
    public static string? WriteDumpDirConfig(string dumperPath, string? outputDir)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            return null;
        try
        {
            string dir = Path.GetDirectoryName(Path.GetFullPath(dumperPath)) ?? ".";
            string cfg = Path.Combine(dir, "il2cpp_dump_dir.txt");
            File.WriteAllText(cfg, outputDir);
            return cfg;
        }
        catch { return null; }
    }

    public static async Task<bool> InjectAsync(
        GameInfo game, int? pid, string dumperPath, Action<string> log, CancellationToken ct, string? outputDir = null)
    {
        bool isLinuxHost = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        if (game.Platform == GamePlatform.Windows && !isLinuxHost)
            return await Task.Run(() => InjectWindows(pid ?? FindPidByPath(game.ExePath), dumperPath, log), ct);

        if (game.Platform == GamePlatform.Windows && isLinuxHost)
            return await InjectWine(game, pid ?? FindPidByPath(game.ExePath), dumperPath, log, ct);

        if (game.Platform == GamePlatform.LinuxNative && isLinuxHost)
            return await InjectLinuxGdb(pid ?? FindPidByPath(game.ExePath), dumperPath, log, ct);

        log("unsupported host/target combination");
        return false;
    }

    /// <summary>Launches a native Linux game with the dumper preloaded.</summary>
    public static Process? LaunchWithPreload(GameInfo game, string soPath, Action<string> log, string? outputDir = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = game.ExePath,
            WorkingDirectory = game.GameDir,
            UseShellExecute = false,
        };
        psi.Environment["LD_PRELOAD"] = soPath;
        if (!string.IsNullOrWhiteSpace(outputDir))
            psi.Environment["IL2CPP_DUMP_DIR"] = outputDir;
        log($"launching with LD_PRELOAD={soPath}");
        return Process.Start(psi);
    }

    // ---------------- windows ----------------

    private static bool InjectWindows(int pid, string dllPath, Action<string> log)
    {
        if (pid <= 0)
        {
            log("process not found / not running");
            return false;
        }
        try
        {
            IntPtr proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                      false, pid);
            if (proc == IntPtr.Zero)
            {
                log($"OpenProcess({pid}) failed: {Marshal.GetLastWin32Error()} (try running as admin)");
                return false;
            }
            IntPtr mem = VirtualAllocEx(proc, IntPtr.Zero, (uint)((dllPath.Length + 1) * 2),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (mem == IntPtr.Zero ||
                !WriteProcessMemory(proc, mem, dllPath + '\0', (uint)((dllPath.Length + 1) * 2), out _))
            {
                log("remote allocation/write failed");
                CloseHandle(proc);
                return false;
            }

            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            IntPtr thread = CreateRemoteThread(proc, IntPtr.Zero, 0, loadLib, mem, 0, IntPtr.Zero);
            if (thread == IntPtr.Zero)
            {
                log("CreateRemoteThread failed");
                CloseHandle(proc);
                return false;
            }
            WaitForSingleObject(thread, 15000);
            GetExitCodeThread(thread, out uint code);
            CloseHandle(thread);
            VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
            CloseHandle(proc);
            log(code != 0 ? $"injected (module 0x{code:x})" : "LoadLibraryW returned NULL in target");
            return code != 0;
        }
        catch (Exception e)
        {
            log($"injection failed: {e.Message}");
            return false;
        }
    }

    // ---------------- wine ----------------

    private static async Task<bool> InjectWine(GameInfo game, int pid, string dllPath, Action<string> log, CancellationToken ct)
    {
        string? injector = FindWineInjector();
        if (injector == null)
        {
            log("injector.exe not found (build the mingw target or copy it next to the loader)");
            return false;
        }

        // convert the linux dll path to a windows-style path for the game process
        string winPath = await WinePath(dllPath, ct) ?? "Z:" + dllPath.Replace('/', '\\');

        string procName = Path.GetFileName(game.ExePath);
        log($"wine injector.exe {procName} \"{winPath}\"");
        var psi = new ProcessStartInfo
        {
            FileName = "wine",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        // keep the target's wine prefix (steam/proton games don't use ~/.wine)
        if (pid > 0)
        {
            string? prefix = ReadEnvVar(pid, "WINEPREFIX");
            if (prefix != null)
            {
                psi.Environment["WINEPREFIX"] = prefix;
                log($"using target's WINEPREFIX={prefix}");
            }
        }
        psi.ArgumentList.Add(injector);
        psi.ArgumentList.Add(procName);
        psi.ArgumentList.Add(winPath);
        using var p = Process.Start(psi);
        if (p == null)
        {
            log("failed to start wine");
            return false;
        }
        string stdout = await p.StandardOutput.ReadToEndAsync(ct);
        string stderr = await p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        foreach (var line in (stdout + stderr).Split('\n', StringSplitOptions.RemoveEmptyEntries))
            if (!line.StartsWith("00", StringComparison.Ordinal)) // skip wine fixme noise
                log(line.Trim());
        return p.ExitCode == 0;
    }

    private static string? ReadEnvVar(int pid, string name)
    {
        try
        {
            var env = File.ReadAllText($"/proc/{pid}/environ");
            foreach (var kv in env.Split('\0', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = kv.IndexOf('=');
                if (eq > 0 && kv[..eq] == name)
                    return kv[(eq + 1)..];
            }
        }
        catch { }
        return null;
    }

    private static async Task<string?> WinePath(string linuxPath, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("winepath", "-w")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
            };
            psi.ArgumentList.Add(linuxPath);
            using var p = Process.Start(psi);
            if (p == null) return null;
            string outp = (await p.StandardOutput.ReadToEndAsync(ct)).Trim();
            await p.WaitForExitAsync(ct);
            return p.ExitCode == 0 && outp.Length > 2 ? outp : null;
        }
        catch { return null; }
    }

    // ---------------- linux native ----------------

    private static async Task<bool> InjectLinuxGdb(int pid, string soPath, Action<string> log, CancellationToken ct)
    {
        if (pid <= 0)
        {
            log("process not found — use 'launch with LD_PRELOAD' instead");
            return false;
        }
        log($"gdb attach: dlopen(\"{soPath}\") into pid {pid}");
        var psi = new ProcessStartInfo
        {
            FileName = "gdb",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-q");
        psi.ArgumentList.Add("-p");
        psi.ArgumentList.Add(pid.ToString());
        psi.ArgumentList.Add("-batch");
        psi.ArgumentList.Add("-ex");
        psi.ArgumentList.Add($"call (void*) dlopen(\"{soPath}\", 2)");
        psi.ArgumentList.Add("-ex");
        psi.ArgumentList.Add("detach");
        psi.ArgumentList.Add("-ex");
        psi.ArgumentList.Add("quit");
        using var p = Process.Start(psi);
        if (p == null)
        {
            log("failed to start gdb");
            return false;
        }
        string stdout = await p.StandardOutput.ReadToEndAsync(ct);
        string stderr = await p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        string output = (stdout + stderr).Trim();
        if (output.Length > 0)
            log(output);
        bool ok = output.Contains("= (void *) 0x") && !output.Contains("0x0\n");
        if (!ok)
            log("gdb injection failed (ptrace_scope? try the LD_PRELOAD launch option)");
        return ok;
    }

    // ---------------- shared ----------------

    public static int FindPidByPath(string exePath)
    {
        foreach (var item in ProcessLister.List())
            if (string.Equals(item.Path, exePath, StringComparison.OrdinalIgnoreCase))
                return item.Pid;
        return 0;
    }

    // ---------------- win32 ----------------

    private const uint PROCESS_CREATE_THREAD = 0x0002;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_READWRITE = 0x04;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, string buffer, uint size, out int written);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attrs, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeThread(IntPtr thread, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(IntPtr proc, IntPtr addr, uint size, uint type);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
}
