using Il2CppLoader.Services;

// End-to-end CLI test of the loader services against a target game.
// usage: CliTest <path-to-game-exe> [pid]

string exePath = args[0];
int pid = args.Length > 1 ? int.Parse(args[1]) : 0;

Console.WriteLine("== process lister (wine/native resolution) ==");
var procs = ProcessLister.List();
foreach (var p in procs.Where(p => p.Kind == "WINE" || p.Path.Contains("VRising") || p.Path.Contains("STRAFTAT")))
    Console.WriteLine($"  [{p.Kind}] pid={p.Pid} {p.Name} -> {p.Path}");

Console.WriteLine("== game detection ==");
var proc = procs.FirstOrDefault(p => p.Path == exePath);
var game = GameDetector.FromExecutable(exePath, proc?.Kind == "WINE");
Console.WriteLine($"  platform:  {game.PlatformName}");
Console.WriteLine($"  backend:   {game.BackendName}");
Console.WriteLine($"  unity:     {game.UnityVersion}");
Console.WriteLine($"  metadata:  v{game.MetadataVersion}");
Console.WriteLine($"  data dir:  {game.DataDir}");

if (game.Backend != ScriptingBackend.Il2Cpp)
{
    Console.WriteLine("not il2cpp, stopping here (detection OK)");
    return;
}

Console.WriteLine("== injection ==");
string? dumper = InjectionService.FindDumperLibrary(game.Platform);
Console.WriteLine($"  dumper: {dumper}");
if (dumper == null) { Console.WriteLine("  NO DUMPER FOUND"); return; }

foreach (var f in new[] { game.DumpPath, game.StringsPath, game.LogPath })
    try { File.Delete(f); } catch { }

bool ok = await InjectionService.InjectAsync(game, pid > 0 ? pid : null, dumper, Console.WriteLine, CancellationToken.None);
Console.WriteLine($"injection: {(ok ? "OK" : "FAILED")}");

Console.WriteLine("== waiting for dump ==");
for (int i = 0; i < 240; i++)
{
    await Task.Delay(5000);
    if (File.Exists(game.LogPath))
    {
        var log = File.ReadAllText(game.LogPath);
        if (log.Contains("done."))
        {
            Console.WriteLine(log);
            break;
        }
    }
}
Console.WriteLine(File.Exists(game.DumpPath)
    ? $"CLASSES OK: {new FileInfo(game.DumpPath).Length / 1024 / 1024} MB"
    : "CLASSES MISSING");
Console.WriteLine(File.Exists(game.StringsPath)
    ? $"STRINGS OK: {new FileInfo(game.StringsPath).Length / 1024} KB"
    : "STRINGS MISSING");
