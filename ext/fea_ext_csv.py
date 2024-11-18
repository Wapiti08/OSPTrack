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

class CsvParser:
    def __init__(self, data_path: Path):
        if data_path.suffix == ".parquet":
            self.csv_data = pd.read_parquet(data_path.as_posix())
        else:
            raise f"the format of {data_path} is not supported"

    def parse_key_value(self, data, parent_key=''):
        """
        Recursively parse a nested key-value structure and return a flat dictionary.
        """
        parsed_data = {}
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{parent_key}.{key}" if parent_key else key
                parsed_data.update(self.parse_key_value(value, full_key))
        elif isinstance(data, list):
            for index, item in enumerate(data):
                full_key = f"{parent_key}[{index}]"
                parsed_data.update(self.parse_key_value(item, full_key))
        else:
            parsed_data[parent_key] = data
        return parsed_data


    def fea_ext(self,):
        feature_dict = {}

        # extract package info to columns
        for pack_dict in self.csv_data["Package"]:
            if pack_dict is None:
                continue
            try:
                pack_dict = pack_dict.replace("'", '"')
                pack_dict = json.loads(pack_dict)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")

            for key, value in pack_dict.items():
                if key not in feature_dict:
                    feature_dict[key] = []
    
                feature_dict[key].append(value if value is not None else "")
            
        # extract feature from analysis key --- two separate parts: import and install
        ## define the necessary strings / values
        nece_features = ["Files", "Sockets", "Commands", "DNS"]
        
        for analysis_dict in self.csv_data["Analysis"]:
            if analysis_dict is None:  # Skip if analysis_dict is None
                continue
            
            analysis_dict = analysis_dict.replace('b"', '"')

            try:
                analysis_dict = analysis_dict.replace("'", '"')
                analysis_dict = self.parse_key_value(analysis_dict)
                # analysis_dict = json.loads(analysis_dict)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")

            for key, value in analysis_dict.items():
                if key in ['import', 'install']:
                    for feature in nece_features:
                        new_key = key + '_' + feature
                        if new_key not in feature_dict:
                            feature_dict[new_key] = []
                        
                        # Check if key's value is not None before accessing .get()
                        if value is not None:
                            feature_dict[new_key].append(value.get(feature, ''))
                        else:
                            feature_dict[new_key].append('')
        feature_dict['Label'] = self.csv_data['Label'].to_list()

        # make sure the length of value is the same
        lengths = [len(v) for v in feature_dict.values()]
        assert len(set(lengths)) == 1, f"Lengths of values are not the same: {lengths}"

        return pd.DataFrame(feature_dict)

    def pkl_save(self, file_name, df:pd.DataFrame):
        ''' save to pickle file to make sure the original type is the same
        
        '''
        df.to_pickle(file_name)


if __name__ == "__main__":

    # define the pkg_folder
    pkg_folder = Path.cwd().parent.joinpath("data", "package-analysis-labels.parquet")
    
    csvparser = CsvParser(pkg_folder)
    csv_df = csvparser.fea_ext()
    # csvparser.pkl_save()