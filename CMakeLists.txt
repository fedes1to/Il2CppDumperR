cmake_minimum_required(VERSION 3.20)
project(Il2CppDumperR CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(Il2cppDumperR SHARED
    Il2cppDumperR/main.cpp
)

target_include_directories(Il2cppDumperR PRIVATE Il2cppDumperR)

target_compile_options(Il2cppDumperR PRIVATE
    -Wall
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wno-multichar>
)

if(WIN32)
    # Fully static so the injected DLL has no mingw runtime dependencies.
    set_target_properties(Il2cppDumperR PROPERTIES PREFIX "")
    target_link_options(Il2cppDumperR PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
    target_link_libraries(Il2cppDumperR PRIVATE pthread)
else()
    target_link_libraries(Il2cppDumperR PRIVATE dl pthread)
    set_target_properties(Il2cppDumperR PROPERTIES
        PREFIX "lib"
        POSITION_INDEPENDENT_CODE ON
    )
    # Keep our own symbols hidden; only the loader entry matters.
    target_compile_options(Il2cppDumperR PRIVATE -fvisibility=hidden)
endif()

# ---------------------------------------------------------------------------
# Fake GameAssembly test harness (end-to-end test without a real game)
# ---------------------------------------------------------------------------
option(BUILD_FAKEGAME "Build the fake GameAssembly test harness" ON)

if(BUILD_FAKEGAME)
    add_library(GameAssembly SHARED test/fakegame/fake_assembly.cpp)
    set_target_properties(GameAssembly PROPERTIES PREFIX "")  # GameAssembly.so / .dll

    add_executable(fakegame test/fakegame/host.cpp)
    if(WIN32)
        target_link_options(GameAssembly PRIVATE -static -static-libgcc -static-libstdc++)
        target_link_options(fakegame PRIVATE -static -static-libgcc -static-libstdc++)

        # CLI injector used by the loader (also standalone: wine injector.exe ...)
        add_executable(injector injector/injector.cpp)
        target_link_options(injector PRIVATE -static -static-libgcc -static-libstdc++ -mconsole -municode)
    else()
        target_link_libraries(fakegame PRIVATE dl)
    endif()
endif()
