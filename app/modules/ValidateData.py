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
        if str(type(values)) == "<class 'dict'>" or str(type(keys)) == "<class 'list'>":
            for nested_key, nested_value in values.items():
                other_dict = current_data.get(keys).get(nested_key)
                if str(nested_value) == str(other_dict):
                    return FunctionStatus(
                        status=False, 
                        section=1, 
                        message=f"Value of: {other_dict}: {nested_key}, is equal to new value: {nested_value}"
                    )
                validated_data[f"{keys}.{nested_key}"] = nested_value
        else: validated_data[keys] = values
    return FunctionStatus(status=True, content=validated_data)