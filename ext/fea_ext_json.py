'''
 # @ Create Time: 2024-10-23 11:14:09
 # @ Modified time: 2024-11-15 15:40:35
 # @ Description: parse features from simulated reports in json format
 
 
 '''
from pathlib import Path
import json
import pandas as pd

class JsonParser:
    def __init__(self, data_path: Path):
        self.data_path = data_path

    def create_data(self,):
        data = []
        for json_file in self.data_path.rglob('**/*.json'):
            data.append(self.json_parse(json_file))
        
        return data

    def json_parse(self, json_file):
        # check file extension
        if self.json_file.suffix == 'json':
            with self.json_file.open("r") as fr:
                data = json.load(fr)
        else:
            raise "the format of input file is not compatiable"
        
    def fea_ext(self, data):
        feature_dict = {}
        for json_file in data:
            # extract package info to columns
            for pack_key, value in json_file["Package"].items():
                if pack_key not in feature_dict:
                    feature_dict[pack_key] = []
                feature_dict[pack_key].append(value)
                
            # extract feature from analysis key --- two separate parts: import and install
            ## define the necessary strings / values
            nece_features = ["Files", "Sockets", "Commands", "DNS"]
            
            for keys, _ in json_file["Analysis"]:
                for key in keys:
                    for feature in nece_features:
                        new_key = key + '_' + feature
                        if new_key not in feature_dict:
                            feature_dict[new_key] = []
                        else:
                            feature_dict[new_key].append(json_file["Analysis"][key][feature])
            # make sure the length of value is the same
            lengths = [len(v) for v in feature_dict.values()]
            assert len(set(lengths)) == 1, f"Lengths of values are not the same: {lengths}"

        return pd.DataFrame(feature_dict)


    def label_create(self, df:pd.DataFrame, label:1):
        ''' assign default malicious label: 1
        
        '''
        df['Label'] = len(df) * [label]
        return df
    

    def sub_label_create(self, df:pd.DataFrame, data_metric: pd.DataFrame):
        ''' match the detailed attack_type via ecosystem, name, and version info
        
        :param df: the generated dataframe from json report
        :param data_metric: the dataframe including known malicious package info
        '''
        # initialize sub_label column
        df['sub_label'] = []

        # perform matching and update sub_label
        for _, metric in data_metric.iterrows():
            # match conditions
            match = (
                df['ecosystem'].str.lower().str.startwith(metric['ecosystem'].lower()) &
                (df['name'] == metric['name']) &
                (df['version'] == metric['version'])
            )
            # to lower case and match the first part string
            df.loc[match, 'sub_label'] = metric['attack_type']

        return df
    
    def pkl_save(self, file_name, df:pd.DataFrame):
        ''' save to pickle file to make sure the original type is the same
        
        '''
        df.to_pickle(file_name)

if __name__ == "__main__":
    
    data_path = Path.cwd().parent.joinpath("data","package-analysis-mal","results")

    jsonparser = JsonParser(data_path)

    




