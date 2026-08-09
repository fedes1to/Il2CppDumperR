// host.cpp — minimal "game" executable: loads GameAssembly and idles.
//
// Linux:   LD_PRELOAD=libIl2cppDumperR.so ./fakegame
// Windows: put Il2cppDumperR.dll next to fakegame.exe (loaded below,
//          simulating injection) or inject with the loader.

#include <cstdio>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main() {
#ifdef _WIN32
    if (!LoadLibraryA("GameAssembly.dll")) {
        std::fprintf(stderr, "failed to load GameAssembly.dll\n");
        return 1;
    }
    // simulate the dumper being injected after the game has booted
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    if (!LoadLibraryA("Il2cppDumperR.dll")) {
        std::fprintf(stderr, "failed to load Il2cppDumperR.dll\n");
        return 1;
    }
#else
    if (!dlopen("./GameAssembly.so", RTLD_NOW | RTLD_GLOBAL)) {
        std::fprintf(stderr, "failed to load GameAssembly.so: %s\n", dlerror());
        return 1;
    }
#endif
    std::puts("fake game running...");

    // exercise string literals periodically so the hook can capture real uses
    typedef void (*use_literals_fn)();
    use_literals_fn use_literals = nullptr;
#ifdef _WIN32
    use_literals = (use_literals_fn)GetProcAddress(GetModuleHandleA("GameAssembly.dll"), "fake_use_literals");
#else
    use_literals = (use_literals_fn)dlsym(dlopen("./GameAssembly.so", RTLD_NOW | RTLD_GLOBAL), "fake_use_literals");
#endif
    std::printf("use_literals=%p\n", (void*)use_literals);
    std::fflush(stdout);
    for (int i = 0; i < 100; ++i) {
        if (use_literals)
            use_literals();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}
