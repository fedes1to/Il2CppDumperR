#pragma once
// resolve.hpp — pattern-scanning fallback for the il2cpp API.
//
// When GameAssembly is obfuscated/protected and its il2cpp_* exports are
// stripped or wrapped, the dumper falls back to locating API functions by
// signature. `resolve_by_signature` is registered as the fallback resolver in
// il2cpp-wrapper.h and called once per unresolved export.
//
// NOTE: obfuscated *managed* assemblies (renamed classes/methods in metadata)
// don't need this at all — the dumper reads runtime metadata, so it works
// regardless. This file covers the harder case of a protected native binary.
//
// Extending: add entries to kApiSignatures. `pattern` is an IDA-style
// signature matched against the whole GameAssembly image; the first match is
// treated as the function start ("direct" transform). If you only have a
// reference site (e.g. a call into the function), add a "call_target"
// transform entry: pattern matches the call instruction and the rel32 target
// is returned.

#include <cstring>
#include <vector>
#include "sigz.hpp"
#include "log.hpp"

namespace resolve {

    enum class transform { direct, call_target };

    struct api_sig {
        const char* export_name;
        const char* platform;   // "windows", "linux", "any"
        const char* pattern;
        transform xf;
        const char* note;
    };

    // ---------------------------------------------------------------------
    // Signature DB for protected GameAssembly builds (x64).
    // These are best-effort and version-sensitive — verify against your target
    // and PR new ones.
    // ---------------------------------------------------------------------
    static const api_sig kApiSignatures[] = {
        // Il2CppDomain* il2cpp_domain_get() -> vm::Domain::GetCurrent() (inlined):
        //   mov rax, [rip+s_pDomain] ; ret
        { "il2cpp_domain_get", "any",
          "48 8B 05 ? ? ? ? C3", transform::direct,
          "Domain::GetCurrent inlined (2019.4-2022.x win/linux x64)" },

        // Il2CppThread* il2cpp_thread_current() -> vm::Thread::Current() (inlined):
        // reads the TLS current thread
        //   mov rax, [rip+s_CurrentThreadTlsIndex-ish] ; ...
        // (kept generic; verify per target)
        { "il2cpp_thread_current", "any",
          "48 8B 04 25 ? ? ? ? C3", transform::direct,
          "Thread::Current inlined TLS read (best-effort)" },
    };

    inline void* apply_transform(void* match, transform xf) {
        switch (xf) {
        case transform::direct:
            return match;
        case transform::call_target: {
            auto* p = static_cast<unsigned char*>(match);
            if (p[0] != 0xE8 && p[0] != 0xE9) // call/jmp rel32
                return nullptr;
            int32_t rel;
            std::memcpy(&rel, p + 1, 4);
            return p + 5 + rel;
        }
        }
        return nullptr;
    }

    inline void* resolve_by_signature(const char* export_name) {
        const char* mod = plat::game_assembly_module_name();
        for (const auto& sig : kApiSignatures) {
            if (std::strcmp(sig.export_name, export_name) != 0)
                continue;
            if (std::strcmp(sig.platform, "any") != 0 &&
                std::strcmp(sig.platform, plat::platform_name) != 0)
                continue;
            auto pattern = sigz::make::ida(sig.pattern);
            void* hit = sigz::scan_image_first(mod, pattern);
            if (!hit)
                continue;
            if (void* fn = apply_transform(hit, sig.xf)) {
                dlog::good("resolved %s via signature (%s)", export_name, sig.note);
                return fn;
            }
        }
        return nullptr;
    }

}
