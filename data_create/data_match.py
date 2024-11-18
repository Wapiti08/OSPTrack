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
import re

global ecosystem

ecosystem = ["npm","jcenter","mavencentral","packagist","pypi","rubygems"]

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
            print(f"!! matched one malicious package from bigquery: {ecosystem}, {name}, {version}")


    pkg_df.to_csv(save_path.joinpath("package-analysis-labels.csv"))
    # save to pickle for further analysis
    pkg_df.to_parquet(save_path.joinpath("package-analysis-labels.parquet"))
    return pkg_df


def extract_pack_and_ver(file_name):
    # regular expression to match a filename with version --- current not support for mavencentral ecosystem
    match_res = re.match(r"(.+)-([\d\.]+)\.(tar\.gz|zip|tgz|gem)$", file_name)
    if match_res:
        # return name, version, extension
        return match_res.group(1), match_res.group(2), match_res.group(3)
    return None, None, None
    

def bkc_json_to_csv(bkc_folder, save_path):
    ''' Traverse the given root directory and package names (.tgz, .jar, .zip, etc) at leaf paths,
    and extract the package part and version part
    
    Parameters:
        - root_dir (Path): The root directory to start traversing from.
    
    Returns:
        - List of dict { version: '', name: '', ecosystem: ''}
        
    '''

    # mapping dict from extension to ecosystem name
    ext_eco_map = {
        "tgz": "npm",
        "zip": "packagist",
        "tar.gz": "pypi",
        "gem": "rubygems",
    }

    bkc_dict_list = []
    for file in bkc_folder.rglob("*"):
        if file.is_file():
            file_name = file.name
            name, version, extension = extract_pack_and_ver(file_name)
            if extension:
                bkc_dict_list.append(
                {"ecosystem": ext_eco_map[extension],
                "name": name,
                "version": version}
                    )

    df = pd.DataFrame(bkc_dict_list)
    df.to_csv(save_path.joinpath("bkc_mal.csv"), index=False)


def mal_pkg_json_to_csv(mal_pkg_folder, save_path):
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
    pkg_par_file = Path.cwd().parent.joinpath("data","package-analysis-bigquery","package-analysis.parquet")
    bkc_pkg_folder = Path.cwd().parent.joinpath("data","Backstabbers-Knife-Collection", "samples")

    # match labels
    save_path = Path.cwd().parent.joinpath("data")

    # ------ match label via malicious packages -------
    # create malicious package csv
    # mal_pkg_json_to_csv(mal_pkg_folder, save_path)
    # match labels
    # pkg_mal_file = save_path.joinpath("pkg_mal.csv")
    # pkg_label_match(pkg_par_file, pkg_mal_file, save_path)

    # ------ match label via BKC packages -------
    bkc_json_to_csv(bkc_pkg_folder, save_path)
    bkc_mal_file = save_path.joinpath("bkc_mal.csv")
    pkg_label_match(pkg_par_file, bkc_mal_file, save_path)

