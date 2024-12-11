// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "json.hpp"
#include "il2cpp/il2cpp-api-types.h"
#include "il2cpp/il2cpp-tabledefs.h"

// dummy definitions so the compiler doesn't kill itself
#define DO_API(r, n, p) r (*n) p
#include "il2cpp/il2cpp-api-functions.h"
#undef DO_API

#include "il2cpp/il2cpp-wrapper.h"

HMODULE il2cppHandle;
Il2CppDomain* il2cpp_domain;
const Il2CppImage* il2cpp_corlib;
nlohmann::json il2cpp_classes;

bool is_class_dumped(std::string &className) {
    for (const auto& classInfo : il2cpp_classes) {
        if (classInfo["full_name"] == className) {
            return true;
        }
    }
    return false;
}

void dump_class(Il2CppClass* klass, void* userData) {
    if (klass) {
        // check if we already dumped this class
        const char* class_name = il2cpp_class_get_name(klass);
        const char* assembly_name = il2cpp_class_get_assemblyname(klass);
		const char* namespace_name = il2cpp_class_get_namespace(klass);

		std::string full_name = std::string(il2cpp_class_get_namespace(klass)) + "." + class_name;

		if (is_class_dumped(full_name))
			return;

		nlohmann::json classInfo;
		classInfo["name"] = class_name;
        classInfo["namespace"] = namespace_name;
        classInfo["full_name"] = full_name;
        classInfo["is_interface"] = il2cpp_class_is_interface(klass);

        if (strcmp(class_name, "Object") and !classInfo["is_interface"]) // Object class doesn't have parents
            classInfo["parent"] = il2cpp_class_get_name(il2cpp_class_get_parent(klass));
        
        classInfo["token"] = il2cpp_class_get_type_token(klass);
        classInfo["is_enum"] = il2cpp_class_is_enum(klass);
        classInfo["flags"] = il2cpp_class_get_flags(klass);
        classInfo["image"] = il2cpp_image_get_name(il2cpp_class_get_image(klass));
        classInfo["type"] = il2cpp_type_get_name(il2cpp_class_get_type(klass));
        classInfo["rank"] = il2cpp_class_get_rank(klass);
        classInfo["assembly_name"] = assembly_name;

		// might be unnecessary
        classInfo["is_valuetype"] = il2cpp_class_is_valuetype(klass);
        classInfo["is_blittable"] = il2cpp_class_is_blittable(klass);
        classInfo["value_size"] = il2cpp_class_value_size(klass, nullptr);
        classInfo["array_element_size"] = il2cpp_class_array_element_size(klass);
        classInfo["instance_size"] = il2cpp_class_instance_size(klass);
        classInfo["num_fields"] = il2cpp_class_num_fields(klass);
        classInfo["data_size"] = il2cpp_class_get_data_size(klass);
        classInfo["is_abstract"] = il2cpp_class_is_abstract(klass);
        classInfo["is_generic"] = il2cpp_class_is_generic(klass);
        classInfo["is_inflated"] = il2cpp_class_is_inflated(klass);

        // fields
		nlohmann::json fields;
		void* iter = nullptr;
		FieldInfo* field;
        while ((field = il2cpp_class_get_fields(klass, &iter))) {
            nlohmann::json fieldInfo;
            fieldInfo["name"] = il2cpp_field_get_name(field);
            fieldInfo["flags"] = il2cpp_field_get_flags(field);
            fieldInfo["offset"] = il2cpp_field_get_offset(field);
            fieldInfo["type"] = il2cpp_type_get_name(il2cpp_field_get_type(field));

            fields.push_back(fieldInfo);
        }

        // methods
		nlohmann::json methods;
		iter = nullptr;
		const MethodInfo* method;
        
        std::string class_name_str = class_name;

        while ((method = il2cpp_class_get_methods(klass, &iter))) {
            nlohmann::json methodInfo;
            methodInfo["name"] = il2cpp_method_get_name(method);
			methodInfo["flags"] = il2cpp_method_get_flags(method, 0);
			methodInfo["return_type"] = il2cpp_type_get_name(il2cpp_method_get_return_type(method));
			methodInfo["token"] = il2cpp_method_get_token(method);
            methodInfo["is_generic"] = il2cpp_method_is_generic(method);
            methodInfo["offset"] = (uintptr_t)(method->methodPointer) - (uintptr_t)il2cppHandle;

            methodInfo["param_count"] = il2cpp_method_get_param_count(method);
            if (class_name_str.substr(class_name_str.size() - 2) != "[]") {
                for (int i = 0; i < methodInfo["param_count"]; i++) {
                    methodInfo["params"][i]["name"] = il2cpp_method_get_param_name(method, i);
                    methodInfo["params"][i]["type"] = il2cpp_type_get_name(il2cpp_method_get_param(method, i));
                }
            }


            // might be unnecessary
            methodInfo["declaring_type"] = il2cpp_class_get_name(il2cpp_method_get_declaring_type(method));
            methodInfo["is_inflated"] = il2cpp_method_is_inflated(method);
            methodInfo["is_instance"] = il2cpp_method_is_instance(method);

			methods.push_back(methodInfo);
        }

		// properties
		nlohmann::json properties;
		iter = nullptr;
		const PropertyInfo* propertyC;
        while ((propertyC = il2cpp_class_get_properties(klass, &iter))) {
            PropertyInfo* property = const_cast<PropertyInfo*>(propertyC);
            nlohmann::json propertyInfo;
            propertyInfo["name"] = il2cpp_property_get_name(property);
			propertyInfo["flags"] = il2cpp_property_get_flags(property);
			propertyInfo["parent"] = il2cpp_class_get_name(il2cpp_property_get_parent(property));

            // Manually iterate through methods to find "get_" and "set_" methods
            for (const auto& method : methods) {
                std::string methodName = method["name"];
                std::string expectedGetName = "get_" + propertyInfo["name"].get<std::string>();
                std::string expectedSetName = "set_" + propertyInfo["name"].get<std::string>();

                if (methodName == expectedGetName) {
                    propertyInfo["get_method"] = method;
                    propertyInfo["type"] = il2cpp_type_get_name(il2cpp_method_get_return_type(il2cpp_property_get_get_method(property)));
                }
                if (methodName == expectedSetName) {
                    propertyInfo["set_method"] = method;
                    propertyInfo["type"] = il2cpp_type_get_name(il2cpp_method_get_param(il2cpp_property_get_set_method(property), 0));
                }

            }

            properties.push_back(propertyInfo);

        }

		classInfo["fields"] = fields;
		classInfo["methods"] = methods;
		classInfo["properties"] = properties;

		il2cpp_classes.push_back(classInfo);

        std::cout << "Finished Dumping Class: " << class_name << std::endl;
    }
}

static DWORD WINAPI MainThread(LPVOID lpReserved) {
    // show console
    AllocConsole();
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONOUT$", "w", stderr);

    // Get handle to GameAssembly.dll
	while (!(il2cppHandle = GetModuleHandle(L"GameAssembly.dll")))
		Sleep(100);
    if (il2cppHandle)
        while (!il2cpp_domain_get_assemblies) {
            init_il2cpp_api(il2cppHandle); // Initialize il2cpp api
            Sleep(100);
        }
    else
        std::cerr << "Failed to init il2cpp api" << std::endl;

    while (!il2cpp_is_vm_thread(nullptr))
        Sleep(100);

    il2cpp_domain = il2cpp_domain_get();
    il2cpp_thread_attach(il2cpp_domain); // attach to game

	// dump the game (funky method im aware)
	il2cpp_class_for_each(dump_class, nullptr);

    std::cout << "Finished Dumping All Classes!" << std::endl;

    // delete the file if it already exists
    DeleteFile(L"il2cpp_classes.json");

	// write to file
	WriteFile(
        CreateFile(L"il2cpp_classes.json", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr), 
        il2cpp_classes.dump(4).c_str(), il2cpp_classes.dump(4).length(), nullptr, nullptr
    );

	il2cpp_thread_detach(il2cpp_thread_current());

    std::cout << "Created JSON file at the game's folder. Done!" << std::endl;

	// close console
	fclose(fp);
	FreeConsole();

	FreeLibraryAndExitThread(static_cast<HMODULE>(lpReserved), 0);

    return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}