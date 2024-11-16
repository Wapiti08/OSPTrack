'''
 # @ Create Time: 2024-08-27 15:57:03
 # @ Modified time: 2024-08-27 16:04:56
 # @ Description: parse features from output csv file for simulated reports

 '''

import pandas as pd
import json
from pathlib import Path
import re
import base64
import numpy as np

# Custom encoder to handle numpy arrays
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)


# Custom encoder to handle bytes
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return super(BytesEncoder, self).default(obj)

class CombinedEncoder(BytesEncoder, NumpyEncoder):
    def default(self, obj):
        # BytesEncoder will be checked first, then NdarrayEncoder
        return super(CombinedEncoder, self).default(obj)

class Featurer:
    def __init__(self,):
        pass

    # Extract data
    def extract_features(self, text):
        print(text)
        if isinstance(text, dict):
            # extract the features
            pass
    
    def cmd_concat(self,):
        pass
        
    
    def decode_bytes(self,):
        pass

    def ndarray_to_list(self,):
        pass


if __name__ == "__main__":

    # define the pkg_folder
    pkg_folder = Path.cwd().parent.joinpath("data", "package-analysis-bigquery", "package-analysis.parquet")
    
    df = pd.read_parquet(pkg_folder)
    json_example = df['Analysis'][0]
    featurer_ext = Featurer()
    data = featurer_ext.extract_features(json_example)
    print(data)