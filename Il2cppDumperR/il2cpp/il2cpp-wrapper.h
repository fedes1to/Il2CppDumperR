#pragma once

// import all il2cpp api functions
void init_il2cpp_api(HMODULE handle) {
#define DO_API(r, n, p) {                                 \
    n = (r (*) p) GetProcAddress(handle, #n);             \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}