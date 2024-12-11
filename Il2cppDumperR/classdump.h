#pragma once

void dump_class(Il2CppClass *klass, void *userData)
{
    if (klass)
    {
        // check if we already dumped this class
        const char *class_name = il2cpp_class_get_name(klass);
        const char *namespace_name = il2cpp_class_get_namespace(klass);
        const char *image_name = il2cpp_image_get_name(il2cpp_class_get_image(klass));

        if (!il2cpp_classes[image_name][namespace_name][class_name].is_null())
            return;

        nlohmann::json classInfo;

        classInfo["is_interface"] = il2cpp_class_is_interface(klass);

        if (strcmp(class_name, "Object") && !classInfo["is_interface"]) // Object class doesn't have parents
            classInfo["parent"] = il2cpp_class_get_name(il2cpp_class_get_parent(klass));

        classInfo["token"] = il2cpp_class_get_type_token(klass);
        classInfo["is_enum"] = il2cpp_class_is_enum(klass);
        classInfo["flags"] = il2cpp_class_get_flags(klass);
        classInfo["type"] = il2cpp_type_get_name(il2cpp_class_get_type(klass));
        classInfo["rank"] = il2cpp_class_get_rank(klass);
        classInfo["assembly_name"] = il2cpp_class_get_assemblyname(klass);

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
        void *iter = nullptr;
        FieldInfo *field;
        while ((field = il2cpp_class_get_fields(klass, &iter)))
        {
            nlohmann::json fieldInfo;
            fieldInfo["name"] = il2cpp_field_get_name(field);
            fieldInfo["flags"] = il2cpp_field_get_flags(field);
            fieldInfo["offset"] = il2cpp_field_get_offset(field);

            fields.push_back(fieldInfo);
        }

        // methods
        nlohmann::json methods;
        iter = nullptr;
        const MethodInfo *method;

        std::string class_name_str = class_name;

        while ((method = il2cpp_class_get_methods(klass, &iter)))
        {
            nlohmann::json methodInfo;
            methodInfo["name"] = il2cpp_method_get_name(method);
            methodInfo["flags"] = il2cpp_method_get_flags(method, 0);
            methodInfo["return_type"] = il2cpp_type_get_name(il2cpp_method_get_return_type(method));
            methodInfo["token"] = il2cpp_method_get_token(method);
            methodInfo["is_generic"] = il2cpp_method_is_generic(method);

            uintptr_t methodPointer = (uintptr_t)(method->methodPointer) - (uintptr_t)il2cppHandle;
            if (methodPointer < 1000000000000000) // abstract pointers dont make a whole lot of sense
                methodInfo["offset"] = methodPointer;

            methodInfo["param_count"] = il2cpp_method_get_param_count(method);
            if (class_name_str.substr(class_name_str.size() - 2) != "[]")
            {
                for (int i = 0; i < methodInfo["param_count"]; i++)
                {
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
        const PropertyInfo *propertyC;
        while ((propertyC = il2cpp_class_get_properties(klass, &iter)))
        {
            PropertyInfo *property = const_cast<PropertyInfo *>(propertyC);
            nlohmann::json propertyInfo;
            propertyInfo["name"] = il2cpp_property_get_name(property);
            propertyInfo["flags"] = il2cpp_property_get_flags(property);
            propertyInfo["parent"] = il2cpp_class_get_name(il2cpp_property_get_parent(property));

            // Manually iterate through methods to find "get_" and "set_" methods
            for (const auto &method : methods)
            {
                std::string methodName = method["name"];
                std::string expectedGetName = "get_" + propertyInfo["name"].get<std::string>();
                std::string expectedSetName = "set_" + propertyInfo["name"].get<std::string>();

                if (methodName == expectedGetName)
                {
                    const MethodInfo *get_method = il2cpp_property_get_get_method(property);
                    propertyInfo["get_method"] = method;
                    propertyInfo["type"] = il2cpp_type_get_name(il2cpp_method_get_return_type(get_method));
                }

                if (methodName == expectedSetName)
                {
                    const MethodInfo *set_method = il2cpp_property_get_set_method(property);
                    propertyInfo["set_method"] = method;
                    propertyInfo["type"] = il2cpp_type_get_name(il2cpp_method_get_return_type(set_method));
                }
            }

            properties.push_back(propertyInfo);
        }

        // Add everything to classInfo
        if (!fields.is_null())
            classInfo["fields"] = fields;
        if (!methods.is_null())
            classInfo["methods"] = methods;
        if (!properties.is_null())
            classInfo["properties"] = properties;

        // Add to global dump JSON
        il2cpp_classes[image_name][namespace_name][class_name] = classInfo;

        std::cout << "Finished Dumping Class: " << class_name << std::endl;
    }
}