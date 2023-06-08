from functionTypes.common import FunctionStatus

def validate_data(current_data: dict, new_data: dict):
    validated_data = {}
    for keys, values in new_data.items():
        dict_to_compare = current_data.get(keys)
        if dict_to_compare == values:
            return FunctionStatus(
                status=False, 
                section=0, 
                message=f"Value of {keys}: {dict_to_compare} , is equal to new value: {values}"
            )
        if str(type(values)) == "<class 'dict'>":
            for nested_key, nested_value in values.items():
                current_dict_key = current_data.get(keys)
                if current_dict_key == None:
                    validated_data[keys] = values
                else:
                    key_value = current_dict_key.get(nested_key)
                    if str(nested_value) == str(key_value):
                        return FunctionStatus(
                            status=False, 
                            section=1, 
                            message=f"Value of: {key_value}: {nested_key}, is equal to new value: {nested_value}"
                        )
                    validated_data[f"{keys}.{nested_key}"] = nested_value
                
        else: validated_data[keys] = values
    return FunctionStatus(status=True, content=validated_data)

if __name__ == "__main__":
    ...