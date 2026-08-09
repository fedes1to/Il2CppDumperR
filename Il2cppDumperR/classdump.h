#pragma once
// classdump.h — dumps every il2cpp class (fields, methods, properties) to JSON.
//
// Hardened for multiple Unity versions and partially-stripped builds:
// every il2cpp API call is guarded against a null function pointer, and the
// whole per-class body is wrapped so one bad class can't kill the dump.

#include "state.hpp"
#include "log.hpp"

#define HAVE_API(fn) ((fn) != nullptr)

inline int dumped_class_count = 0;

inline void dump_class(Il2CppClass *klass, void * /*userData*/)
{
    if (!klass || !HAVE_API(il2cpp_class_get_name))
        return;

    try
    {
        const char *class_name = il2cpp_class_get_name(klass);
        if (!class_name)
            return;
        const char *namespace_name = HAVE_API(il2cpp_class_get_namespace) ? il2cpp_class_get_namespace(klass) : "";
        const char *image_name = "?";
        if (HAVE_API(il2cpp_class_get_image) && HAVE_API(il2cpp_image_get_name))
        {
            const Il2CppImage *img = il2cpp_class_get_image(klass);
            if (img)
                image_name = il2cpp_image_get_name(img);
        }
        if (!namespace_name)
            namespace_name = "";
        if (!image_name)
            image_name = "?";

        // check if we already dumped this class
        if (!il2cpp_classes[image_name][namespace_name][class_name].is_null())
            return;

        nlohmann::json classInfo;

        if (HAVE_API(il2cpp_class_is_interface))
            classInfo["is_interface"] = il2cpp_class_is_interface(klass);

        if (strcmp(class_name, "Object") && !classInfo.value("is_interface", false) && HAVE_API(il2cpp_class_get_parent))
        {
            if (Il2CppClass *parent = il2cpp_class_get_parent(klass))
                if (const char *parent_name = il2cpp_class_get_name(parent))
                    classInfo["parent"] = parent_name;
        }

        if (HAVE_API(il2cpp_class_get_type_token))
            classInfo["token"] = il2cpp_class_get_type_token(klass);
        if (HAVE_API(il2cpp_class_is_enum))
            classInfo["is_enum"] = il2cpp_class_is_enum(klass);
        if (HAVE_API(il2cpp_class_get_flags))
            classInfo["flags"] = il2cpp_class_get_flags(klass);
        if (HAVE_API(il2cpp_class_get_type) && HAVE_API(il2cpp_type_get_name))
        {
            if (const char *tn = il2cpp_type_get_name(il2cpp_class_get_type(klass)))
                classInfo["type"] = tn;
        }
        if (HAVE_API(il2cpp_class_get_rank))
            classInfo["rank"] = il2cpp_class_get_rank(klass);
        if (HAVE_API(il2cpp_class_get_assemblyname))
        {
            if (const char *an = il2cpp_class_get_assemblyname(klass))
                classInfo["assembly_name"] = an;
        }

        // extra metadata (all optional, version dependent)
        if (HAVE_API(il2cpp_class_is_valuetype))
            classInfo["is_valuetype"] = il2cpp_class_is_valuetype(klass);
        if (HAVE_API(il2cpp_class_is_blittable))
            classInfo["is_blittable"] = il2cpp_class_is_blittable(klass);
        if (HAVE_API(il2cpp_class_value_size))
            classInfo["value_size"] = il2cpp_class_value_size(klass, nullptr);
        if (HAVE_API(il2cpp_class_array_element_size))
            classInfo["array_element_size"] = il2cpp_class_array_element_size(klass);
        if (HAVE_API(il2cpp_class_instance_size))
            classInfo["instance_size"] = il2cpp_class_instance_size(klass);
        if (HAVE_API(il2cpp_class_num_fields))
            classInfo["num_fields"] = il2cpp_class_num_fields(klass);
        if (HAVE_API(il2cpp_class_get_data_size))
            classInfo["data_size"] = il2cpp_class_get_data_size(klass);
        if (HAVE_API(il2cpp_class_is_abstract))
            classInfo["is_abstract"] = il2cpp_class_is_abstract(klass);
        if (HAVE_API(il2cpp_class_is_generic))
            classInfo["is_generic"] = il2cpp_class_is_generic(klass);
        if (HAVE_API(il2cpp_class_is_inflated))
            classInfo["is_inflated"] = il2cpp_class_is_inflated(klass);

        // fields
        nlohmann::json fields;
        if (HAVE_API(il2cpp_class_get_fields) && HAVE_API(il2cpp_field_get_name))
        {
            void *iter = nullptr;
            FieldInfo *field;
            while ((field = il2cpp_class_get_fields(klass, &iter)))
            {
                nlohmann::json fieldInfo;
                if (const char *fn = il2cpp_field_get_name(field))
                    fieldInfo["name"] = fn;
                if (HAVE_API(il2cpp_field_get_flags))
                    fieldInfo["flags"] = il2cpp_field_get_flags(field);
                if (HAVE_API(il2cpp_field_get_offset))
                    fieldInfo["offset"] = il2cpp_field_get_offset(field);
                if (HAVE_API(il2cpp_field_get_type) && HAVE_API(il2cpp_type_get_name))
                {
                    if (const char *ft = il2cpp_type_get_name(il2cpp_field_get_type(field)))
                        fieldInfo["type"] = ft;
                }
                fields.push_back(fieldInfo);
            }
        }

        // methods
        nlohmann::json methods;
        if (HAVE_API(il2cpp_class_get_methods) && HAVE_API(il2cpp_method_get_name))
        {
            void *iter = nullptr;
            const MethodInfo *method;
            std::string class_name_str = class_name;

            while ((method = il2cpp_class_get_methods(klass, &iter)))
            {
                nlohmann::json methodInfo;
                if (const char *mn = il2cpp_method_get_name(method))
                    methodInfo["name"] = mn;
                if (HAVE_API(il2cpp_method_get_flags))
                    methodInfo["flags"] = il2cpp_method_get_flags(method, nullptr);
                if (HAVE_API(il2cpp_method_get_return_type) && HAVE_API(il2cpp_type_get_name))
                {
                    if (const char *rt = il2cpp_type_get_name(il2cpp_method_get_return_type(method)))
                        methodInfo["return_type"] = rt;
                }
                if (HAVE_API(il2cpp_method_get_token))
                    methodInfo["token"] = il2cpp_method_get_token(method);
                if (HAVE_API(il2cpp_method_is_generic))
                    methodInfo["is_generic"] = il2cpp_method_is_generic(method);

                // methodPointer is the first member of MethodInfo on every Unity version
                uintptr_t methodPointer = (uintptr_t)(method->methodPointer) - (uintptr_t)il2cppBase;
                if (il2cppBase && method->methodPointer && methodPointer < 0x10000000) // abstract pointers dont make a whole lot of sense
                    methodInfo["offset"] = methodPointer;

                int param_count = HAVE_API(il2cpp_method_get_param_count) ? il2cpp_method_get_param_count(method) : 0;
                methodInfo["param_count"] = param_count;
                if (class_name_str.size() < 2 || class_name_str.substr(class_name_str.size() - 2) != "[]")
                {
                    for (int i = 0; i < param_count; i++)
                    {
                        if (HAVE_API(il2cpp_method_get_param_name))
                            if (const char *pn = il2cpp_method_get_param_name(method, i))
                                methodInfo["params"][i]["name"] = pn;
                        if (HAVE_API(il2cpp_method_get_param) && HAVE_API(il2cpp_type_get_name))
                            if (const char *pt = il2cpp_type_get_name(il2cpp_method_get_param(method, i)))
                                methodInfo["params"][i]["type"] = pt;
                    }
                }

                if (HAVE_API(il2cpp_method_get_declaring_type))
                    if (Il2CppClass *dt = il2cpp_method_get_declaring_type(method))
                        if (const char *dtn = il2cpp_class_get_name(dt))
                            methodInfo["declaring_type"] = dtn;
                if (HAVE_API(il2cpp_method_is_inflated))
                    methodInfo["is_inflated"] = il2cpp_method_is_inflated(method);
                if (HAVE_API(il2cpp_method_is_instance))
                    methodInfo["is_instance"] = il2cpp_method_is_instance(method);

                methods.push_back(methodInfo);
            }
        }

        // properties
        nlohmann::json properties;
        if (HAVE_API(il2cpp_class_get_properties) && HAVE_API(il2cpp_property_get_name))
        {
            void *iter = nullptr;
            const PropertyInfo *propertyC;
            while ((propertyC = il2cpp_class_get_properties(klass, &iter)))
            {
                PropertyInfo *property = const_cast<PropertyInfo *>(propertyC);
                nlohmann::json propertyInfo;
                if (const char *pn = il2cpp_property_get_name(property))
                    propertyInfo["name"] = pn;
                if (HAVE_API(il2cpp_property_get_flags))
                    propertyInfo["flags"] = il2cpp_property_get_flags(property);
                if (HAVE_API(il2cpp_property_get_parent))
                    if (Il2CppClass *pp = il2cpp_property_get_parent(property))
                        if (const char *ppn = il2cpp_class_get_name(pp))
                            propertyInfo["parent"] = ppn;

                // Match get_/set_ accessors from the already-dumped method list.
                // NOTE: arg count is checked so we bind get (0 args) / set (1 arg)
                // to the correct overload.
                for (const auto &method : methods)
                {
                    std::string methodName = method.value("name", "");
                    std::string expectedGetName = "get_" + propertyInfo.value("name", "");
                    std::string expectedSetName = "set_" + propertyInfo.value("name", "");
                    int pc = method.value("param_count", -1);

                    if (methodName == expectedGetName && pc == 0)
                    {
                        propertyInfo["get_method"] = method;
                        propertyInfo["type"] = method.value("return_type", "");
                    }

                    if (methodName == expectedSetName && pc == 1)
                    {
                        propertyInfo["set_method"] = method;
                        if (method.contains("params") && !method["params"].empty())
                            propertyInfo["type"] = method["params"][0].value("type", "");
                    }
                }

                properties.push_back(propertyInfo);
            }
        }

        // Add everything to classInfo
        if (!fields.empty())
            classInfo["fields"] = fields;
        if (!methods.empty())
            classInfo["methods"] = methods;
        if (!properties.empty())
            classInfo["properties"] = properties;

        // Add to global dump JSON
        il2cpp_classes[image_name][namespace_name][class_name] = classInfo;

        if (++dumped_class_count % 500 == 0)
            dlog::info("dumped %d classes...", dumped_class_count);
    }
    catch (...)
    {
        dlog::warn("exception while dumping a class, skipping");
    }
}
