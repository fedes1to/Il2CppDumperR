// host.cpp — minimal "game" executable: loads GameAssembly and idles.
//
// Linux:   LD_PRELOAD=libIl2cppDumperR.so ./fakegame
// Windows: put Il2cppDumperR.dll next to fakegame.exe (loaded below,
//          simulating injection) or inject with the loader.

#include <cstdio>
#include <thread>
#include <chrono>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
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
    {
        // absolute path so the dumper's get_module finds the SAME instance
        char self[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        std::string dir = n > 0 ? std::string(self, n).substr(0, std::string(self, n).find_last_of('/')) : ".";
        std::string ga = dir + "/GameAssembly.so";
        if (!dlopen(ga.c_str(), RTLD_NOW | RTLD_GLOBAL)) {
            std::fprintf(stderr, "failed to load %s: %s\n", ga.c_str(), dlerror());
            return 1;
        }
        std::printf("loaded %s\n", ga.c_str());
    }
#endif
    std::puts("fake game running...");

    // exercise string literals periodically so the hook can capture real uses
    typedef void (*use_literals_fn)();
    use_literals_fn use_literals = nullptr;
#ifdef _WIN32
    use_literals = (use_literals_fn)GetProcAddress(GetModuleHandleA("GameAssembly.dll"), "fake_use_literals");
#else
    use_literals = (use_literals_fn)dlsym(RTLD_DEFAULT, "fake_use_literals");
#endif
    std::printf("use_literals=%p\n", (void*)use_literals);
    std::fflush(stdout);
    for (int i = 0; i < 200; ++i) {
        if (use_literals)
            use_literals();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}
