'''
 # @ Create Time: 2024-08-24 16:09:22
 # @ Modified time: 2024-08-24 16:09:24
 # @ Description: match the malicious software from package-analysis 
 through malicious-packages until 8.27.2024

 '''
import pandas as pd
import json
from pathlib import Path
from tqdm import tqdm
import ast


# define process for npm
def load_json_file(json_file: Path) -> json:
    with json_file.open("r") as fr:
        return json.load(fr)

def pkg_label_match(pkg_data_file, pkg_mal_file, save_path):
    ''' match the package with available labels

    param pkg_data: 
        structured with package (metadata), CreatedTimestamp, Analysis 
                        (dict type with both dynamic and static data)
    param pkg_mal_list: 
        structured with json format, describing wiwth basic information in key-value
    
    return: matching labels with malicious
    '''
    # read package parquet dataset
    pkg_df = pd.read_parquet(pkg_data_file)
    pkg_mal_df = pd.read_csv(pkg_mal_file)

    # add initial labels
    pkg_df["Label"] = [0] * len(pkg_df)
    
    # get the package ecosystem, name --- string
    pkg_info_list = pkg_df["Package"].to_list() 

    for index, pkg_info in tqdm(enumerate(pkg_info_list), desc="matching labels", \
                                     total=len(pkg_df)):
        pkg_info = ast.literal_eval(pkg_info)
        ecosystem = pkg_info["Ecosystem"]
        version = pkg_info["Version"]
        name = pkg_info["Name"]
        
        # check whether they match same row
        match = pkg_mal_df[
            (pkg_mal_df["name"] == name) & (pkg_mal_df["version"] == version) &
            (pkg_mal_df["ecosystem"] == ecosystem)
            ]
        
        if not match.empty:
            # label this package as malicious label --- 1
            pkg_df["Label"][index] = 1
    pkg_df.to_csv(save_path.joinpath("package-analysis-labels.csv"))
    print(pkg_df.Label.value_counts())
    return pkg_df


def pkg_bkc_match():
    ''' match labels from BKC dataset
    
    '''
    pass


def feature_ext(pkg_data):
    ''' extract features from package-analysis dataset
    
    '''
    pass

    

def bkc_json_to_csv(mal_pkg_folder, save_path):
    ''' collect all json files and convert them to csv
    
    '''
    mal_dict_list = []
    for json_file in mal_pkg_folder.rglob("**/*.json"):
        # bypass some directories names with .json
        if json_file.is_file():
            json_info = load_json_file(json_file)

        affect_dict = json_info["affected"][0]
        try:
            version = affect_dict["versions"][0]
        except:
            # there is no version information for some ecosystem (npm)
            version = ""

        mal_dict_list.append(
            {"ecosystem": affect_dict["package"]["ecosystem"],
             "name": affect_dict["package"]["name"],
             "version": version}
        )

    df = pd.DataFrame(mal_dict_list)
    df.to_csv(save_path.joinpath("pkg_mal.csv"), index=False)


def json_to_csv(mal_pkg_folder, save_path):
    ''' collect all json files and convert them to csv
    
    '''
    mal_dict_list = []
    for json_file in mal_pkg_folder.rglob("**/*.json"):
        # bypass some directories names with .json
        if json_file.is_file():
            json_info = load_json_file(json_file)

        affect_dict = json_info["affected"][0]
        try:
            version = affect_dict["versions"][0]
        except:
            # there is no version information for some ecosystem (npm)
            version = ""

        mal_dict_list.append(
            {"ecosystem": affect_dict["package"]["ecosystem"],
             "name": affect_dict["package"]["name"],
             "version": version}
        )

    df = pd.DataFrame(mal_dict_list)
    df.to_csv(save_path.joinpath("pkg_mal.csv"), index=False)


if __name__ == "__main__":
    # define the mal_pkg_folder
    mal_pkg_folder = Path.cwd().parent.joinpath("data","malicious-packages","osv","malicious")
    pkg_par_file = Path.cwd().parent.joinpath("data","package-analysis.parquet")

    # match labels
    save_path = Path.cwd().parent.joinpath("data")
    # create malicious package csv
    json_to_csv(mal_pkg_folder, save_path)
    # match labels
    pkg_mal_file = save_path.joinpath("pkg_mal.csv")
    pkg_label_match(pkg_par_file, pkg_mal_file, save_path)