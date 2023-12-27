def is_iterable(value):
    try:
        iter(value)
        return True
    except TypeError:
        return False

def matchDicts(dict_base: dict, dict_to_compare: dict):
  found_match_dict = {}
  for k, v in dict_base.items():
      other_dict_key = dict_to_compare.get(k)
      if other_dict_key == v:
          pass
        
      if str(type(v)) == "<class 'dict'>" or str(type(k)) == "<class 'list'>":
        for uk, uv in v.items():
          other_dict = dict_to_compare.get(k).get(uk)
          if str(uv) == str(other_dict):
            pass
          
          found_match_dict[f"{k}.{uk}"] = uv
          
      else:
        found_match_dict[k] = v #   CHANGE[k][uk] = uv
        
  return found_match_dict

if __name__ == "__main__":
    ...