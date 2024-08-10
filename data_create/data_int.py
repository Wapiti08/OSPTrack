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

# define the target directory
data_path = Path.cwd().parent.joinpath("data")

# fetch all filenames of chunks
csv_files = data_path.glob("package-analysis-*.csv")

# initialize a blank dataframe
combined_df = pd.DataFrame()

# use universe column names
columns = None

# traverse all csv files
for file in csv_files:
    df = pd.read_csv(file)
    
    if columns is None:
        columns = df.columns

    combined_df = pd.concat([combined_df, df])

# reset index
combined_df.reset_index(drop=True, inplace=True)

combined_df.to_csv(Path(data_path).joinpath("package-analysis.csv").as_posix(), index=False)
combined_df.to_parquet(Path(data_path).joinpath("package-analysis.parquet").as_posix(), index=False)