'''
 # @ Create Time: 2024-07-29 09:28:03
 # @ Modified time: 2024-07-29 10:15:19
 # @ Description: integate chunks of package data to one single dataset
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import os
import pandas as pd


def inte_csv():
    # define the target directory
    data_path = Path.cwd().parent.joinpath("data")

    # fetch all csv of chunks
    csv_files = data_path.glob("package-analysis-*.csv")
    # optional
    csv_files = [file for file in csv_files if file.stem.split('-')[-1].isdigit()]
    # initialize a blank dataframe
    combined_df = pd.DataFrame()

    for file in csv_files:
        df = pd.read_csv(file)
        combined_df = pd.concat([combined_df, df])

    # reset index
    combined_df.reset_index()

    combined_df.to_csv(Path(data_path).joinpath("package-analysis.csv").as_posix(), index=False)

if __name__=="__main__":
    inte_csv()
    # save to parquest as well
    pkg_folder = Path.cwd().parent.joinpath("data","package-analysis.csv")
    
    df = pd.read_csv(pkg_folder)
    data_path = Path.cwd().parent.joinpath("data")
    target_parquet = Path(data_path).joinpath("package-analysis.parquet").as_posix()
    df.to_parquet(target_parquet, engine="pyarrow", index=False)
