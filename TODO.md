# Il2CppDumperR — Roadmap / TODO

Order of execution (as requested):

- [x] **1. Port to MinGW** — removed MSVC-isms (`freopen_s`, PCH, MinHook include, WideCharToMultiByte),
      CMake build, cross-compiles the dumper DLL on Linux with `x86_64-w64-mingw32`.
      Verified: `build/mingw/Il2cppDumperR.dll` builds clean.
- [x] **2. Linux support** — platform abstraction (`platform.hpp`): native `.so` dumper build
      (dlopen/dlsym, `/proc/self/maps`), works against native Linux Unity games AND under Wine.
      `sigz.hpp` updated to upstream (github.com/creaffy/sigz) + portable backend.
      Verified end-to-end with the fake-GameAssembly harness (`test/run_fake_test.sh`,
      all checks green) and under Wine (`build/fake-run-win`).
- [~] **3. README cleanup** — drop "DummyDll creation" / "dump.cs creation" from TODO, document
      the new loader, IDA script and JSON workflow. (final rewrite once loader lands)
- [ ] **4. Loader** — new Avalonia app (`Il2CppLoader`) with proper UI, Linux + Windows:
      process picker, Unity version auto-detect (globalgamemanagers / UnityPlayer), inject
      (LoadLibrary via CreateRemoteThread on Windows / `wine injector.exe` under Wine /
      LD_PRELOAD + gdb-dlopen for native Linux), dump progress, output folder.
- [~] **5. Multiple Unity versions** — runtime metadata-version detection (global-metadata.dat),
      per-export graceful fallback (unresolved APIs are logged, not fatal),
      per-platform/per-version signature tables in strings.hpp / resolve.hpp.
      (extend signature DBs as more targets get tested)
- [x] **6. Strings** — string literals recovered from memory (metadata string literal table):
      pattern-scan `s_StringLiteralTable` (signature DB + generic RIP-relative heuristic),
      strict `Il2CppString` validation, dumps `il2cpp_strings.json`.
      Verified on Linux and Wine.
- [ ] **7. IDA script** — `ida/il2cpp_import.py`: import `il2cpp_classes.json` +
      `il2cpp_strings.json`, rename methods by RVA, create structs for fields, apply comments/strings.
- [~] **8. Obfuscated assemblies** — pattern-scanning fallback resolver (`resolve.hpp`) for the
      il2cpp API when GameAssembly exports are stripped/wrapped (export first, signature DB
      fallback). Managed-name obfuscation needs nothing: we read runtime metadata.

Nice-to-have (explicitly out of scope): DummyDll creation, dump.cs creation.
