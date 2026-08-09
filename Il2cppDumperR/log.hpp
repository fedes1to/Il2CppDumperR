#pragma once
// log.hpp — tiny logger, writes to stdout and mirrors to il2cpp_dumper.log
// next to the game executable so headless injections are still observable.

#include <cstdio>
#include <cstdarg>
#include <string>
#include <fstream>
#include <iostream>

#include "platform.hpp"

namespace dlog {
    inline std::ofstream& file() {
        static std::ofstream f(plat::executable_dir() + "/il2cpp_dumper.log",
                               std::ios::out | std::ios::trunc);
        return f;
    }

    inline void vwrite(const char* prefix, const char* fmt, va_list args) {
        char buf[4096];
        std::vsnprintf(buf, sizeof(buf), fmt, args);
        std::fputs(prefix, stdout);
        std::fputs(buf, stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
        if (file().is_open()) {
            file() << prefix << buf << '\n';
            file().flush();
        }
    }

    inline void info(const char* fmt, ...) {
        va_list a; va_start(a, fmt);
        vwrite("[*] ", fmt, a);
        va_end(a);
    }

    inline void good(const char* fmt, ...) {
        va_list a; va_start(a, fmt);
        vwrite("[+] ", fmt, a);
        va_end(a);
    }

    inline void warn(const char* fmt, ...) {
        va_list a; va_start(a, fmt);
        vwrite("[!] ", fmt, a);
        va_end(a);
    }

    inline void error(const char* fmt, ...) {
        va_list a; va_start(a, fmt);
        vwrite("[-] ", fmt, a);
        va_end(a);
    }
}
