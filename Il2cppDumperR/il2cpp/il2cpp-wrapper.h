#pragma once
// il2cpp-wrapper.h — resolves the il2cpp API from GameAssembly.
//
// Every export is resolved independently and failures are recorded in
// il2cpp_unresolved_apis instead of crashing, so the dumper degrades
// gracefully across Unity versions (some exports only exist on newer/older
// versions) and can fall back to pattern scanning (obfuscated/protected
// GameAssembly builds, see resolve.hpp).

#include <vector>
#include <string>
#include "../platform.hpp"

inline std::vector<std::string> il2cpp_unresolved_apis;

// Optional hook: given an export name, return a function pointer found via
// signature scanning. Registered by resolve.hpp when exports are missing.
using il2cpp_fallback_resolver_t = void* (*)(const char* export_name);
inline il2cpp_fallback_resolver_t il2cpp_fallback_resolver = nullptr;

// import all il2cpp api functions
inline void init_il2cpp_api(plat::module_handle handle) {
    il2cpp_unresolved_apis.clear();
#define DO_API(r, n, p) {                                   \
    n = (r (*) p) plat::get_proc(handle, #n);               \
    if (!n && il2cpp_fallback_resolver)                     \
        n = (r (*) p) il2cpp_fallback_resolver(#n);         \
    if (!n)                                                 \
        il2cpp_unresolved_apis.push_back(#n);               \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}
