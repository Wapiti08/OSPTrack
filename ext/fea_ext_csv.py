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
from tqdm import tqdm

class CsvParser:
    def __init__(self, data_path: Path):
        self.data_path = data_path
    
    def create_data(self,):
        data = []
        for par_file in self.data_path.rglob('**/*.parquet'):
            par_df = pd.read_parquet(par_file)
            if not par_df.empty:
                data.append(par_df)
        
        return data

    # def parse_key_value(self, data, parent_key=''):
    #     """
    #     Recursively parse a nested key-value structure and return a flat dictionary.
    #     """
    #     parsed_data = {}
    #     if isinstance(data, dict):
    #         for key, value in data.items():
    #             full_key = f"{parent_key}.{key}" if parent_key else key
    #             parsed_data.update(self.parse_key_value(value, full_key))
    #     elif isinstance(data, list):
    #         for index, item in enumerate(data):
    #             full_key = f"{parent_key}[{index}]"
    #             parsed_data.update(self.parse_key_value(item, full_key))
    #     else:
    #         parsed_data[parent_key] = data
    #     return parsed_data


    def fea_ext(self, data):
        feature_dict = {}

        # extract package info to columns
        for par_df in data:
            for pack_dict in par_df['Package']:
                for key, value in pack_dict.items():
                    if key not in feature_dict:
                        feature_dict[key] = []
                    feature_dict[key].append(value if value is not None else "")
            
            # extract feature from analysis key --- two separate parts: import and install
            ## define the necessary strings / values
            nece_features = ["Files", "Sockets", "Commands", "DNS"]
            
            for analysis_dict in par_df["Analysis"]:
                if analysis_dict is None:  # Skip if analysis_dict is None
                    continue

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

        # make sure the length of value is the same
        lengths = [len(v) for v in feature_dict.values()]
        assert len(set(lengths)) == 1, f"Lengths of values are not the same: {lengths}"

        return pd.DataFrame(feature_dict)
    
    def label_match(self, data_df, label_file):

        pkg_mal_df = pd.read_csv(label_file)
        data_df['Label'] = [0]* len(data_df)

        for index, row in tqdm(data_df.iterrows(), desc="matching labels", \
                        total=len(data_df)):
            ecosystem = row["Ecosystem"]
            version = row["Version"]
            name = row["Name"]

            # check whether they match same row
            match = pkg_mal_df[
                (pkg_mal_df["name"] == name) & (pkg_mal_df["version"] == version) &
                (pkg_mal_df["ecosystem"] == ecosystem)
                ]
            
            if not match.empty:
                # label this package as malicious label --- 1
                data_df["Label"][index] = 1

        return data_df


    def pkl_save(self, file_name, df:pd.DataFrame):
        ''' save to pickle file to make sure the original type is the same
        
        '''
        df.to_pickle(file_name)


if __name__ == "__main__":

    # define the pkg_folder
    label_file = Path.cwd().parent.joinpath("data", "package-analysis-labels.parquet")
    pkg_data = Path.cwd().parent.joinpath("data", "package-analysis-bigquery")
    bkc_mal_file = Path.cwd().parent.joinpath("data", "bkc_mal.csv")

    
    csvparser = CsvParser(pkg_data)

    csv_df = csvparser.fea_ext()
    # csvparser.pkl_save()