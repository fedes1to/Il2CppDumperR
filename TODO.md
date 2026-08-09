# Il2CppDumperR — Roadmap / TODO

All items below are complete. See the README for usage.

- [x] **1. Port to MinGW** — removed MSVC-isms (`freopen_s`, PCH, MinHook include, WideCharToMultiByte),
      CMake build, cross-compiles the dumper DLL on Linux with `x86_64-w64-mingw32`.
      Verified: `build/mingw/Il2cppDumperR.dll` builds clean.
- [x] **2. Linux support** — platform abstraction (`platform.hpp`): native `.so` dumper build
      (dlopen/dlsym, `/proc/self/maps`, `/proc/self/mem`), works against native Linux Unity games
      AND under Wine. `sigz.hpp` updated to upstream (github.com/creaffy/sigz) + portable backend.
      Verified end-to-end with the fake-GameAssembly harness (`test/run_fake_test.sh`, all checks
      green) and under Wine (`build/fake-run-win`).
- [x] **3. README cleanup** — DummyDll creation / dump.cs creation dropped from the roadmap;
      README documents the loader, IDA script and JSON workflow.
- [x] **4. Loader** — Avalonia app (`Il2CppLoader`) with proper UI, Linux + Windows:
      process picker (Wine processes resolved via cmdline, WINEPREFIX inherited), Unity version
      auto-detect (globalgamemanagers / global-metadata.dat), inject (CreateRemoteThread on
      Windows / `wine injector.exe` under Wine / gdb-dlopen or LD_PRELOAD for native Linux),
      dump progress log, output folder picker.
- [x] **5. Multiple Unity versions** — runtime metadata-version detection (global-metadata.dat
      header, versions 24–31+), per-export graceful fallback (unresolved APIs logged, not fatal),
      per-platform/per-version signature tables in strings.hpp / resolve.hpp, auto-detected
      Il2CppStringLiteralDefinition field order.
- [x] **6. Strings (memory-only by default)** — string literals recovered from process memory:
      pattern-scan `s_StringLiteralTable` (signature DB + generic RIP-relative heuristic with
      metadata-assisted validation), strict `Il2CppString` validation, race-free safe_read.
      **MEMORY-ONLY by default**: global-metadata.dat is used only to validate the found table
      and know its size — never to fabricate values. Set `IL2CPP_STRINGS_ALLOW_METADATA=1` to
      opt into the file fallback. Verified on the real game (V Rising DS): 7.3k literals from
      memory, all `source: "memory"`.
- [x] **7. IDA script** — `ida/il2cpp_import.py`: import `il2cpp_classes.json` +
      `il2cpp_strings.json`, rename methods by RVA, create structs for fields, apply comments/strings.
- [x] **8. Obfuscated assemblies** — pattern-scanning fallback resolver (`resolve.hpp`) for the
      il2cpp API when GameAssembly exports are stripped/wrapped (export first, signature DB
      fallback). Managed-name obfuscation needs nothing: we read runtime metadata.

## Completed extras

- [x] **String xrefs** — finds the s_StringLiteralTable slot dynamically (writable slot whose
      value == the heap table pointer), scans GameAssembly code for RIP-relative refs to it,
      annotates methods with `string_count` / `strings` (indices) and string entries with
      `methods`. Verified on the real game (V Rising DS: slot discovered, 7 literal-using sites,
      method annotated). Dedicated-server builds strip most string-heavy client code from
      IL2CPP, so counts are low there — client builds will have thousands.
- [x] **Output path control** — dumps go to the game folder by default; the loader can pick a
      different output folder. Mechanism: `il2cpp_dump_dir.txt` next to the dumper module
      (works for Windows/Wine/Linux injection alike), or `IL2CPP_DUMP_DIR` env var
      (set by the loader for LD_PRELOAD launches). Verified under Wine.
- [x] **Fix .gitignore** — loader bin/obj, CliTest bin/obj, fake-run scratch, steamcmd and
      downloaded test games are ignored.

## Out of scope

- DummyDll creation, dump.cs creation (the JSON + IDA script replace that workflow).
