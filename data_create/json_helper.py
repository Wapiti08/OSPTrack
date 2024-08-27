'''
 # @ Create Time: 2024-08-27 15:57:03
 # @ Modified time: 2024-08-27 16:04:56
 # @ Description:
 '''

import pandas as pd
import json
from pathlib import Path
import re

def extract_keys_tree(json_obj):
    """Recursively extracts all keys from a JSON object in a tree structure.
    
    Args:
        json_obj (dict or list): The JSON object to parse.
    
    Returns:
        dict: A dictionary representing the tree structure of keys.
    """

    if isinstance(json_obj, dict):
        # For a dictionary, create a nested structure for each key
        tree = {}
        for key, value in json_obj.items():
            tree[key] = extract_keys_tree(value)
        return tree
    
    elif isinstance(json_obj, list):
        # For a list, process each element and merge keys
        tree = {}
        for item in json_obj:
            item_tree = extract_keys_tree(item)
            for k, v in item_tree.items():
                if k in tree:
                    tree[k].update(v)
                else:
                    tree[k] = v
        return tree
    
    else:
        # Base case: return an empty dict for primitive types
        return {}


def extract_keys_from_json(json_str):
    """Parses a JSON string and extracts all keys in a tree structure.
    
    Args:
        json_str (str): The JSON string to parse.
    
    Returns:
        dict: A dictionary representing the tree structure of keys.
    """
    # replace all ' with "
    pattern = r"(?<=\{|,)\s*'([^']+?)'\s*(?=\s*:)"
    # remove all the \n
    
    # Replace single quotes with double quotes
    json_str = re.sub(pattern, r'"\1"', json_str)
    try:
        print(json_str[:100])
        # Load the JSON string into a Python object
        json_obj = json.loads(json_str)
        # Extract the key structure
        return extract_keys_tree(json_obj)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON string: {e}")
        return {}


if __name__ == "__main__":
    # define the pkg_folder
    pkg_folder = Path.cwd().parent.joinpath("data","package-analysis.parquet")
    df = pd.read_parquet(pkg_folder)
    json_example = df["Analysis"][0]
    print(extract_keys_from_json(json_example))
