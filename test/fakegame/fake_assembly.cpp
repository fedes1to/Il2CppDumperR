// fake_assembly.cpp — a fake "GameAssembly" module that exports just enough of
// the il2cpp API to exercise Il2CppDumperR end-to-end without a real game.
//
// Builds as GameAssembly.so (linux) or GameAssembly.dll (windows/mingw).

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <initializer_list>

#if defined(_WIN32)
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#endif

typedef char16_t Il2CppChar;

// ---------------------------------------------------------------------------
// Fake runtime objects
// ---------------------------------------------------------------------------

struct FakeString { // layout compatible with Il2CppString
    void* klass;
    void* monitor;
    int32_t length;
    Il2CppChar chars[128];
};

struct FakeField {
    const char* name;
    int flags;
    size_t offset;
    const char* type_name;
};

struct FakeMethod { // first member must be methodPointer (MethodInfo layout)
    void* methodPointer;
    const char* name;
    const char* return_type;
    const char* param_names[4];
    const char* param_types[4];
    int param_count;
    uint32_t token;
    int flags;
};

struct FakeProperty {
    const char* name;
    int flags;
};

struct FakeClass {
    const char* name;
    const char* namespaze;
    const char* image;
    const char* assembly;
    FakeClass* parent;
    int flags;
    int is_interface;
    int is_enum;
    int is_generic;
    FakeField* fields;
    int num_fields;
    FakeMethod* methods;
    int num_methods;
    FakeProperty* props;
    int num_props;
};

// dummy code so methodPointer values land inside this module
static void dummy_take_damage() {}
static void dummy_get_health() {}
static void dummy_set_health(int) {}
static void dummy_die() {}

static FakeClass g_object;   // System.Object (corlib)
static FakeClass g_string;   // System.String (klass of string literals)
static FakeClass g_player;   // Game.Player (Assembly-CSharp)
static FakeClass g_enemy;    // Game.Enemy
static FakeClass g_iface;    // Game.IDamageable (interface)

static FakeField g_player_fields[] = {
    { "health", 0x0006, 0x10, "System.Int32" },
    { "playerName", 0x0001, 0x18, "System.String" },
};
static FakeMethod g_player_methods[] = {
    { (void*)&dummy_take_damage, "TakeDamage", "System.Void", { "amount" }, { "System.Single" }, 1, 0x06000001, 0x0086 },
    { (void*)&dummy_get_health, "get_Health", "System.Int32", {}, {}, 0, 0x06000002, 0x0086 },
    { (void*)&dummy_set_health, "set_Health", "System.Void", { "value" }, { "System.Int32" }, 1, 0x06000003, 0x0086 },
    { nullptr, "OnRemoved", "System.Void", {}, {}, 0, 0x06000004, 0x0486 }, // abstract: no pointer
};
static FakeProperty g_player_props[] = {
    { "Health", 0 },
};

static FakeMethod g_enemy_methods[] = {
    { (void*)&dummy_die, "Die", "System.Void", {}, {}, 0, 0x06000010, 0x0086 },
};

static void init_classes() {
    g_object = { "Object", "System", "corlib.dll", "mscorlib", nullptr, 0x100001, 0, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0 };
    g_string = { "String", "System", "corlib.dll", "mscorlib", &g_object, 0x100001, 0, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0 };
    g_iface = { "IDamageable", "Game", "Assembly-CSharp.dll", "Assembly-CSharp", &g_object, 0x1000a1, 1, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0 };
    g_player = { "Player", "Game", "Assembly-CSharp.dll", "Assembly-CSharp", &g_object, 0x100001, 0, 0, 0,
                 g_player_fields, 2, g_player_methods, 4, g_player_props, 1 };
    g_enemy = { "Enemy", "Game", "Assembly-CSharp.dll", "Assembly-CSharp", &g_object, 0x100001, 0, 0, 0,
                nullptr, 0, g_enemy_methods, 1, nullptr, 0 };
}

// ---------------------------------------------------------------------------
// Fake string literal table (exercises strings.hpp)
// ---------------------------------------------------------------------------

static FakeString g_literals[8];
static FakeString* s_StringLiteralTable[8];

static void make_string(FakeString* s, const char* utf8) {
    s->klass = &g_string;
    s->monitor = nullptr;
    size_t n = std::strlen(utf8);
    s->length = (int32_t)n;
    for (size_t i = 0; i < n; ++i)
        s->chars[i] = (Il2CppChar)(unsigned char)utf8[i];
    s->chars[n] = 0;
}

static void init_strings() {
    const char* values[] = {
        "player_name", "ui/main_menu", "Hello, world!", "damage",
        "critical_hit", "inventory_full", "level_01", "gg ez"
    };
    for (int i = 0; i < 8; ++i) {
        make_string(&g_literals[i], values[i]);
        s_StringLiteralTable[i] = &g_literals[i];
    }
}

// exported so the compiler emits a RIP-relative reference to the table;
// the dumper's heuristic scan finds the table through it.
EXPORT void* fake_touch_strings() {
    return s_StringLiteralTable[0];
}

// ---------------------------------------------------------------------------
// Fake literal dispatcher (mimics il2cpp MetadataCache::GetStringLiteral):
// takes an encoded token (type<<29 | idx<<1 | 1), type 5 = string literal.
// The dumper's hook targets this function's prologue.
// ---------------------------------------------------------------------------

static int g_fake_dispatch_calls = 0;

// The dispatcher's prologue must be exactly 5 clean bytes for the hook to
// steal them (push rdi; sub rsp,20h — same as real il2cpp). Implemented as
// a naked wrapper that jumps to the C++ body after the standard prologue.
extern "C" void* fake_literal_dispatcher(unsigned int token) __attribute__((naked));
extern "C" void* fake_literal_dispatcher_body(unsigned int token);
extern "C" void* fake_literal_dispatcher(unsigned int token) {
    __asm__ volatile(
        "push %rdi\n\t"          // 57
        "sub $0x20, %rsp\n\t"    // 48 83 EC 20
        "call fake_literal_dispatcher_body\n\t"
        "add $0x20, %rsp\n\t"
        "pop %rdi\n\t"
        "ret\n\t"
    );
}
extern "C" void* fake_literal_dispatcher_body(unsigned int token) {
    unsigned int type = token >> 29;
    unsigned int idx = (token >> 1) & 0xFFFFFFF;
    ++g_fake_dispatch_calls;
    std::printf("DISPATCH body: token=0x%x calls=%d this=%p\n", token, g_fake_dispatch_calls, (void*)&fake_literal_dispatcher_body);
    std::fflush(stdout);
    if (type == 5 && idx < 8)
        return s_StringLiteralTable[idx];
    return nullptr;
}

EXPORT void fake_use_literals() {
    // exercise a few literal indices through the dispatcher
    for (unsigned int idx : {0u, 1u, 4u, 7u}) {
        unsigned int token = (5u << 29) | (idx << 1) | 1u;
        fake_literal_dispatcher(token);
    }
}

// ---------------------------------------------------------------------------
// il2cpp API exports
// ---------------------------------------------------------------------------

static int g_domain = 0;

EXPORT int il2cpp_is_vm_thread(void*) { return 1; }
EXPORT void* il2cpp_domain_get() { return &g_domain; }
EXPORT void* il2cpp_thread_attach(void*) { return (void*)0x1; }
EXPORT void* il2cpp_thread_current() { return (void*)0x1; }
EXPORT void il2cpp_thread_detach(void*) {}

static FakeClass* g_all_classes[] = { &g_object, &g_string, &g_iface, &g_player, &g_enemy };

EXPORT void il2cpp_class_for_each(void (*cb)(void*, void*), void* userData) {
    for (auto* k : g_all_classes)
        cb(k, userData);
}

EXPORT const char* il2cpp_class_get_name(void* k) { return ((FakeClass*)k)->name; }
EXPORT const char* il2cpp_class_get_namespace(void* k) { return ((FakeClass*)k)->namespaze; }
EXPORT void* il2cpp_class_get_image(void* k) { return (void*)((FakeClass*)k)->image; }
EXPORT const char* il2cpp_image_get_name(const void* img) { return (const char*)img; }
EXPORT int il2cpp_class_is_interface(void* k) { return ((FakeClass*)k)->is_interface; }
EXPORT void* il2cpp_class_get_parent(void* k) { return ((FakeClass*)k)->parent; }
EXPORT uint32_t il2cpp_class_get_type_token(void*) { return 0x02000001; }
EXPORT int il2cpp_class_is_enum(void* k) { return ((FakeClass*)k)->is_enum; }
EXPORT int il2cpp_class_get_flags(void* k) { return ((FakeClass*)k)->flags; }
EXPORT void* il2cpp_class_get_type(void* k) { return (void*)((FakeClass*)k)->name; }
EXPORT const char* il2cpp_type_get_name(const void* t) { return (const char*)t; }
EXPORT int il2cpp_class_get_rank(void*) { return 0; }
EXPORT const char* il2cpp_class_get_assemblyname(const void* k) { return ((const FakeClass*)k)->assembly; }
EXPORT int il2cpp_class_is_valuetype(const void*) { return 0; }
EXPORT int il2cpp_class_is_blittable(const void*) { return 0; }
EXPORT int32_t il2cpp_class_value_size(void*, uint32_t*) { return 0; }
EXPORT int il2cpp_class_array_element_size(const void*) { return 0; }
EXPORT int32_t il2cpp_class_instance_size(void*) { return 0x40; }
EXPORT size_t il2cpp_class_num_fields(const void* k) { return ((const FakeClass*)k)->num_fields; }
EXPORT uint32_t il2cpp_class_get_data_size(const void*) { return 0x40; }
EXPORT int il2cpp_class_is_abstract(const void*) { return 0; }
EXPORT int il2cpp_class_is_generic(const void* k) { return ((const FakeClass*)k)->is_generic; }
EXPORT int il2cpp_class_is_inflated(const void*) { return 0; }

EXPORT void* il2cpp_class_get_fields(void* k, void** iter) {
    FakeClass* c = (FakeClass*)k;
    uintptr_t i = (uintptr_t)*iter;
    if (i >= (uintptr_t)c->num_fields)
        return nullptr;
    *iter = (void*)(i + 1);
    return &c->fields[i];
}
EXPORT const char* il2cpp_field_get_name(void* f) { return ((FakeField*)f)->name; }
EXPORT int il2cpp_field_get_flags(void* f) { return ((FakeField*)f)->flags; }
EXPORT size_t il2cpp_field_get_offset(void* f) { return ((FakeField*)f)->offset; }
EXPORT void* il2cpp_field_get_type(void*) { return nullptr; }
// note: il2cpp_field_get_type returns nullptr here to exercise the guard path

EXPORT const void* il2cpp_class_get_methods(void* k, void** iter) {
    FakeClass* c = (FakeClass*)k;
    uintptr_t i = (uintptr_t)*iter;
    if (i >= (uintptr_t)c->num_methods)
        return nullptr;
    *iter = (void*)(i + 1);
    return &c->methods[i];
}
EXPORT const char* il2cpp_method_get_name(const void* m) { return ((const FakeMethod*)m)->name; }
EXPORT uint32_t il2cpp_method_get_flags(const void* m, uint32_t*) { return ((const FakeMethod*)m)->flags; }
EXPORT const void* il2cpp_method_get_return_type(const void* m) { return (const void*)((const FakeMethod*)m)->return_type; }
EXPORT uint32_t il2cpp_method_get_token(const void* m) { return ((const FakeMethod*)m)->token; }
EXPORT int il2cpp_method_is_generic(const void*) { return 0; }
EXPORT int il2cpp_method_get_param_count(const void* m) { return ((const FakeMethod*)m)->param_count; }
EXPORT const char* il2cpp_method_get_param_name(const void* m, uint32_t i) { return ((const FakeMethod*)m)->param_names[i]; }
EXPORT const void* il2cpp_method_get_param(const void* m, uint32_t i) { return (const void*)((const FakeMethod*)m)->param_types[i]; }
EXPORT void* il2cpp_method_get_declaring_type(const void*) { return &g_player; }
EXPORT int il2cpp_method_is_inflated(const void*) { return 0; }
EXPORT int il2cpp_method_is_instance(const void*) { return 1; }

EXPORT const void* il2cpp_class_get_properties(void* k, void** iter) {
    FakeClass* c = (FakeClass*)k;
    uintptr_t i = (uintptr_t)*iter;
    if (i >= (uintptr_t)c->num_props)
        return nullptr;
    *iter = (void*)(i + 1);
    return &c->props[i];
}
EXPORT const char* il2cpp_property_get_name(void* p) { return ((FakeProperty*)p)->name; }
EXPORT uint32_t il2cpp_property_get_flags(void* p) { return ((FakeProperty*)p)->flags; }
EXPORT void* il2cpp_property_get_parent(void*) { return &g_player; }

// ---------------------------------------------------------------------------
// module init
// ---------------------------------------------------------------------------

#if defined(_WIN32)
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        init_classes();
        init_strings();
    }
    return TRUE;
}
#else
__attribute__((constructor)) static void fake_init() {
    init_classes();
    init_strings();
}
#endif
