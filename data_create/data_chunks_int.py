'''
 # @ Create Time: 2024-07-29 09:28:03
 # @ Modified time: 2024-07-29 10:15:19
 # @ Description: integate chunks of package data to one single dataset
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from google.cloud import bigquery
import os
import pandas as pd
from tqdm import tqdm
import pyarrow.parquet as pq
import pyarrow as pa

def inte_csv():
    # define the target directory
    data_path = Path.cwd().parent.joinpath("data")

    # fetch all csv of chunks
    csv_files = data_path.glob("package-analysis-*.csv")

    # initialize a blank dataframe
    combined_df = pd.DataFrame()

    for file in csv_files:
        df = pd.read_csv(file)
        combined_df = pd.concat([combined_df, df])

    # reset index
    combined_df.reset_index()

    combined_df.to_csv(Path(data_path).joinpath("package-analysis.csv").as_posix(), index=False)


def inte_parquets():
    def flatten_df(df):
        return pd.json_normalize(df.to_dict(orient='records'))
    
    # define the target directory
    data_path = Path.cwd().parent.joinpath("data")
    # fetch all parquet of chunks
    parquet_files = data_path.glob("package-analysis-*.parquet")
 
    dfs = []

    # Read each Parquet file and append its DataFrame to the list
    for file in parquet_files:
        df = pd.read_parquet(file)
        df = flatten_df(df)
        dfs.append(df)

    # Concatenate all DataFrames
    combined_par_df = pd.concat(dfs, ignore_index=True)

    # Optionally reset index if needed
    combined_par_df.reset_index(drop=True, inplace=True)
    
    combined_par_df.to_parquet(Path(data_path).joinpath("package-analysis.parquet").as_posix(), index=False)

if __name__=="__main__":
    inte_csv()
    inte_parquets()