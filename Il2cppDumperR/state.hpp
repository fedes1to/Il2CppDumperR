#pragma once
// state.hpp — globals shared across the dumper (single translation unit,
// inline variables keep it tidy).

#include "json.hpp"
#include "platform.hpp"
#include "metadata.hpp"
#include "il2cpp/il2cpp-api-types.h"

inline plat::module_handle il2cppHandle = nullptr;   // GameAssembly module handle
inline void* il2cppBase = nullptr;                   // GameAssembly base address
inline Il2CppDomain* il2cpp_domain = nullptr;
inline const Il2CppImage* il2cpp_corlib = nullptr;
inline nlohmann::json il2cpp_classes = nlohmann::json::object();
inline nlohmann::json il2cpp_strings = nlohmann::json::array();
inline meta::MetadataInfo il2cpp_metadata;           // global-metadata.dat (version + string literals)
inline int il2cpp_metadata_version = 0;              // convenience copy of il2cpp_metadata.version
