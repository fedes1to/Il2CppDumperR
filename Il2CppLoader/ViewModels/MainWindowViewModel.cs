using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Il2CppLoader.Services;

namespace Il2CppLoader.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    private readonly IClassicDesktopStyleApplicationLifetime _desktop;
    private CancellationTokenSource? _watchCts;

    public MainWindowViewModel(IClassicDesktopStyleApplicationLifetime desktop)
    {
        _desktop = desktop;
        RefreshProcesses();
    }

    // ---------------- state ----------------

    [ObservableProperty]
    private ObservableCollection<ProcessItem> _processes = new();

    [ObservableProperty]
    private string _processFilter = "";

    partial void OnProcessFilterChanged(string value) => RefreshProcesses();

    [ObservableProperty]
    private ProcessItem? _selectedProcess;

    [ObservableProperty]
    private string _gamePath = "";

    [ObservableProperty]
    private string _dumperPathOverride = "";

    [ObservableProperty]
    private string _outputFolder = "";

    [ObservableProperty]
    private GameInfo? _game;

    [ObservableProperty]
    private string _statusText = "select a running game or browse for its executable";

    [ObservableProperty]
    private string _logText = "";

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _canInject;

    partial void OnSelectedProcessChanged(ProcessItem? value)
    {
        if (value != null && !string.IsNullOrEmpty(value.Path) && File.Exists(value.Path))
        {
            GamePath = value.Path;
            Detect(value.Path, value.Kind == "WINE");
        }
    }

    partial void OnGamePathChanged(string value)
    {
        if (File.Exists(value))
            Detect(value, SelectedProcess?.Kind == "WINE");
    }

    // ---------------- detection ----------------

    private void Detect(string exePath, bool underWine)
    {
        try
        {
            Game = GameDetector.FromExecutable(exePath, underWine);
            CanInject = Game.Backend == ScriptingBackend.Il2Cpp;
            StatusText = Game.Backend switch
            {
                ScriptingBackend.Il2Cpp => "ready to dump",
                ScriptingBackend.Mono => "this is a Mono game — Il2CppDumperR only works on IL2CPP games",
                _ => "could not detect the scripting backend — is this a Unity game?",
            };
        }
        catch (Exception e)
        {
            StatusText = $"detection failed: {e.Message}";
            Game = null;
            CanInject = false;
        }
    }

    // ---------------- commands ----------------

    [RelayCommand]
    private void RefreshProcesses()
    {
        var list = ProcessLister.List();
        if (!string.IsNullOrWhiteSpace(ProcessFilter))
            list = list.Where(p => p.Name.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase) ||
                                    p.Path.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        Processes = new ObservableCollection<ProcessItem>(list);
    }

    [RelayCommand]
    private async Task BrowseGame()
    {
        var window = _desktop.MainWindow;
        if (window == null)
            return;
        var files = await window.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select the game executable",
            AllowMultiple = false,
        });
        var file = files.FirstOrDefault();
        if (file?.TryGetLocalPath() is string path)
            GamePath = path;
    }

    [RelayCommand]
    private async Task Inject()
    {
        if (Game == null || IsBusy)
            return;
        if (Game.Backend != ScriptingBackend.Il2Cpp)
        {
            AppendLog("not an IL2CPP game, refusing to inject");
            return;
        }

        IsBusy = true;
        _watchCts?.Cancel();
        _watchCts = new CancellationTokenSource();
        var ct = _watchCts.Token;

        try
        {
            string? dumper = InjectionService.FindDumperLibrary(Game.Platform, DumperPathOverride);
            if (dumper == null)
            {
                AppendLog("dumper library not found — build it (build.sh) or set the path override");
                return;
            }
            AppendLog($"dumper: {dumper}");

            // output folder: UI-chosen, else the game folder
            string outDir = string.IsNullOrWhiteSpace(OutputFolder) ? Game.GameDir : OutputFolder;
            AppendLog($"output folder: {outDir}");
            // the dumper reads il2cpp_dump_dir.txt from its own module dir
            InjectionService.WriteDumpDirConfig(dumper, outDir);

            // remove previous output so we can watch for fresh files
            foreach (var f in new[] { Path.Combine(outDir, "il2cpp_classes.json"), Path.Combine(outDir, "il2cpp_strings.json"), Path.Combine(outDir, "il2cpp_dumper.log") })
                try { File.Delete(f); } catch { }

            int? pid = SelectedProcess?.Pid;
            if (pid.HasValue && !string.Equals(SelectedProcess!.Path, Game.ExePath, StringComparison.OrdinalIgnoreCase))
                pid = null; // stale selection

            bool ok = await InjectionService.InjectAsync(Game, pid, dumper, AppendLog, ct, outDir);
            if (!ok)
            {
                AppendLog("injection failed");
                StatusText = "injection failed — see log";
                return;
            }

            AppendLog("injected, waiting for the dump...");
            StatusText = "dumping...";
            await WatchDump(Game, outDir, ct);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task LaunchPreload()
    {
        if (Game == null || Game.Platform != GamePlatform.LinuxNative)
        {
            AppendLog("LD_PRELOAD launch is only for native Linux games");
            return;
        }
        string? dumper = InjectionService.FindDumperLibrary(Game.Platform, DumperPathOverride);
        if (dumper == null)
        {
            AppendLog("libIl2cppDumperR.so not found — build it (build.sh) or set the path override");
            return;
        }
        string outDir = string.IsNullOrWhiteSpace(OutputFolder) ? Game.GameDir : OutputFolder;
        foreach (var f in new[] { Path.Combine(outDir, "il2cpp_classes.json"), Path.Combine(outDir, "il2cpp_strings.json"), Path.Combine(outDir, "il2cpp_dumper.log") })
            try { File.Delete(f); } catch { }
        InjectionService.LaunchWithPreload(Game, dumper, AppendLog, outDir);
        StatusText = "game launched, dumping...";
        _watchCts?.Cancel();
        _watchCts = new CancellationTokenSource();
        await WatchDump(Game, outDir, _watchCts.Token);
    }

    [RelayCommand]
    private async Task BrowseOutputFolder()
    {
        var window = _desktop.MainWindow;
        if (window == null)
            return;
        var dirs = await window.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select output folder for the dump",
            AllowMultiple = false,
        });
        var dir = dirs.FirstOrDefault();
        if (dir?.TryGetLocalPath() is string path)
            OutputFolder = path;
    }

    [RelayCommand]
    private void OpenOutputFolder()
    {
        string outDir = string.IsNullOrWhiteSpace(OutputFolder) ? Game?.GameDir ?? "" : OutputFolder;
        if (string.IsNullOrEmpty(outDir))
            return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = outDir,
                UseShellExecute = true,
            });
        }
        catch (Exception e)
        {
            AppendLog($"could not open folder: {e.Message}");
        }
    }

    // ---------------- dump watching ----------------

    private async Task WatchDump(GameInfo game, string outDir, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddMinutes(10);
        long lastLogSize = 0;
        bool done = false;
        string logPath = Path.Combine(outDir, "il2cpp_dumper.log");
        string dumpPath = Path.Combine(outDir, "il2cpp_classes.json");
        string stringsPath = Path.Combine(outDir, "il2cpp_strings.json");

        while (!ct.IsCancellationRequested && DateTime.UtcNow < deadline)
        {
            // mirror the dumper log
            try
            {
                if (File.Exists(logPath))
                {
                    var fi = new FileInfo(logPath);
                    if (fi.Length > lastLogSize)
                    {
                        using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        fs.Seek(lastLogSize, SeekOrigin.Begin);
                        using var sr = new StreamReader(fs);
                        AppendLog((await sr.ReadToEndAsync(ct)).TrimEnd());
                        lastLogSize = fi.Length;
                        if (LogText.Contains("done."))
                            done = true;
                    }
                }
            }
            catch { }

            if (done || (File.Exists(dumpPath) && LogText.Contains("wrote")))
            {
                // give the strings file a moment to land too
                await Task.Delay(1500, ct);
                break;
            }
            await Task.Delay(500, ct);
        }

        if (File.Exists(dumpPath))
        {
            var size = new FileInfo(dumpPath).Length;
            string strings = File.Exists(stringsPath)
                ? $", strings {new FileInfo(stringsPath).Length / 1024} KB"
                : "";
            StatusText = $"dump complete ({size / 1024 / 1024} MB classes{strings})";
            AppendLog($"dump at: {dumpPath}");
        }
        else
        {
            StatusText = "timed out waiting for the dump";
        }
    }

    private void AppendLog(string text)
    {
        if (string.IsNullOrEmpty(text))
            return;
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            LogText += text + "\n";
        });
    }
}
