# Il2CppDumperR

Runtime dumper for IL2CPP games — Windows, Wine and native Linux.

Injects into a running game and writes JSON dumps next to the game executable:

- **`il2cpp_classes.json`** — every class with fields (+offsets), methods (+RVA into
  GameAssembly), properties, tokens, sizes and flags
- **`il2cpp_strings.json`** — every string literal, read **from live memory**
  (`source: "memory"`). By default the dumper is memory-only: `global-metadata.dat`
  is used solely to validate the found table and know its size, never to
  fabricate values. Set `IL2CPP_STRINGS_ALLOW_METADATA=1` to also fill
  lazily-uncreated literals from the metadata blob (`source: "metadata"`).
  String xrefs are also built: methods that reference literals get
  `string_count` / `strings` (literal indices), and string entries get
  `methods` (the methods that use them).

Works across Unity versions (metadata versions 24–31+, Unity 5.6 → 2022.2+ era):
every il2cpp export is resolved independently and the dump degrades gracefully
instead of crashing; version-sensitive structures are auto-detected from
`global-metadata.dat`. Protected/obfuscated GameAssembly builds are handled with
a pattern-scanning fallback resolver (`resolve.hpp`), and the string literal
table is located with a signature DB + a generic RIP-relative heuristic
(`strings.hpp`). Managed-name obfuscation doesn't matter at all — everything is
read from runtime metadata.

## Components

| Path | What |
|---|---|
| `Il2cppDumperR/` | the dumper itself (C++23, single TU, CMake) |
| `Il2CppLoader/` | Avalonia UI loader/injector (Windows + Linux) |
| `injector/` | tiny CLI injector (`injector.exe`) used under Wine / standalone |
| `ida/il2cpp_import.py` | IDAPython importer for the JSON dumps |
| `test/` | fake-GameAssembly harness + loader CLI test |

## Building

Everything builds on Linux:

```bash
./build.sh            # native linux .so + windows .dll (via mingw-w64)
./build.sh linux      # build/linux/libIl2cppDumperR.so
./build.sh windows    # build/mingw/Il2cppDumperR.dll + injector.exe

cd Il2CppLoader && dotnet build -c Release   # the UI loader
```

The dumper also builds on Windows with MSVC through CMake
(`cmake -G "Visual Studio 17 2022"`).

## Usage

### Loader (recommended)

Run `Il2CppLoader`, pick the running game (Wine processes are resolved
automatically, including the right `WINEPREFIX`) or browse to the game
executable. It auto-detects platform / scripting backend / Unity version /
metadata version, then **Inject & Dump**. Watch progress in the log panel.

Output goes to the game folder by default; set the **Output folder** box to
write elsewhere (the loader drops an `il2cpp_dump_dir.txt` next to the dumper,
which the dumper reads on startup — so it works identically on Windows, Wine
and native Linux).

### Manual

**Windows / Wine:**

```
injector.exe Game.exe "C:\path\to\Il2cppDumperR.dll"
wine injector.exe Game.exe "Z:\path\to\Il2cppDumperR.dll"   # from linux
```

**Native Linux** (launch-time, always works):

```bash
LD_PRELOAD=/path/to/libIl2cppDumperR.so ./Game.x86_64
```

**Native Linux** (attach to a running game — needs `kernel.yama.ptrace_scope=0`):

```bash
gdb -q -p $(pidof Game.x86_64) -batch \
    -ex 'call (void*) dlopen("/path/to/libIl2cppDumperR.so", 2)' \
    -ex detach -ex quit
```

### IDA

Open `GameAssembly.dll`/`.so` in IDA, let autoanalysis finish, then
`File → Script file… → ida/il2cpp_import.py`:

- methods are renamed to `Namespace.Class::Method` and functions created at
  their RVAs
- a struct per class is created with fields at their offsets
- tokens / return types / signatures land in comments
- string literals are imported into an `il2cpp_str` segment (searchable with Alt+T)

## JSON format

`il2cpp_classes.json`: `image → namespace → class → { fields, methods, properties, ... }`.
Method `offset` is the RVA of the method body relative to GameAssembly's base.

`il2cpp_strings.json`: `[{ index, value, source: "memory" | "metadata", rva? }]`.
`index` is the string literal index used by the compiled code.

## Testing

```bash
./test/run_fake_test.sh   # end-to-end against a fake GameAssembly (all checks)
```

Also verified against a real game (V Rising Dedicated Server, Unity 2022.3.58f1,
metadata v31, under Wine): ~38.5k classes, 32.1k string literals.

## TODO / roadmap

See [TODO.md](TODO.md).

Explicitly out of scope: DummyDll creation, dump.cs creation (the JSON + IDA
script replace that workflow).
