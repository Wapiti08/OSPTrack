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
            json_data = self.json_parse(json_file)
            if json_data:
                data.append(json_data)
        
        return data

    def json_parse(self, json_file):
        # check file extension
        if json_file.suffix == '.json' and json_file.stat().st_size!=0:
            with json_file.open("r") as fr:
                data = json.load(fr)
                return data
        else:
            print(f"the format of input file {json_file} is not compatiable")
            return None
        
    def fea_ext(self, data):
        feature_dict = {}
        for json_data in data:
            # extract package info to columns
            for pack_key, value in json_data["Package"].items():
                if pack_key not in feature_dict:
                    feature_dict[pack_key] = []
                feature_dict[pack_key].append(value if value is not None else '')

            # extract feature from analysis key --- two separate parts: import and install
            ## define the necessary strings / values
            nece_features = ["Files", "Sockets", "Commands", "DNS"]
            
            # Check if "Analysis" is a dictionary before processing
            required_keys = {'import', 'install'}
            if isinstance(json_data.get("Analysis"), dict):
                for key in required_keys:
                    # Only process the key if it exists in Analysis
                    if key in json_data["Analysis"]:
                        for feature in nece_features:
                            new_key = key + '_' + feature
                            if new_key not in feature_dict:
                                feature_dict[new_key] = []
                            
                            # Append the feature value if exists, otherwise append ''
                            feature_value = json_data["Analysis"][key].get(feature, '')
                            feature_dict[new_key].append(feature_value)
                    else:
                        # If 'import' or 'install' is missing, ensure blank values for each feature
                        for feature in nece_features:
                            new_key = key + '_' + feature
                            if new_key not in feature_dict:
                                feature_dict[new_key] = []
                            feature_dict[new_key].append('')

            else:
                # If "Analysis" is not a dictionary, append blank values for all keys
                for key in ['import', 'install']:
                    for feature in nece_features:
                        new_key = key + '_' + feature
                        if new_key not in feature_dict:
                            feature_dict[new_key] = []
                        feature_dict[new_key].append('')

        # make sure the length of value is the same
        lengths = [len(v) for v in feature_dict.values()]
        assert len(set(lengths)) == 1, f"Lengths of values are not the same: {lengths}"

        return pd.DataFrame(feature_dict)


    def label_create(self, df:pd.DataFrame, label=1):
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
        df['Sub_Label'] = len(df) * ['']

        # perform matching and update sub_label
        for _, metric in data_metric.iterrows():
            # match conditions
            match = (
                df['Ecosystem'].str.lower().str.startswith(metric['pkg_type'].lower()) &
                (df['Name'] == metric['name']) &
                (df['Version'] == metric['version'])
            )
            # to lower case and match the first part string
            df.loc[match, 'Sub_Label'] = metric['attack_type']

        return df
    
    def pkl_save(self, file_name, df:pd.DataFrame):
        ''' save to pickle file to make sure the original type is the same
        
        '''
        df.to_pickle(file_name)

if __name__ == "__main__":
    
    data_path = Path.cwd().parent.joinpath("data","package-analysis-mal","results")

    jsonparser = JsonParser(data_path)

    




