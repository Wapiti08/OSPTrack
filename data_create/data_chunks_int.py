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
from fastparquet import ParquetFile
import pyarrow as pa
import numpy as np
import dask.dataframe as dd


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
    # # Define the target directory
    data_path = Path.cwd().parent.joinpath("data")
    # # Fetch all parquet files
    parquet_files = data_path.glob("package-analysis-*.parquet")
    
    # # Load and concatenate using Dask
    # ddf = dd.read_parquet(list(parquet_files))
    
    # # Compute to get the final DataFrame
    # combined_par_df = ddf.compute()
    
    # # Save the combined DataFrame to a new Parquet file
    # combined_par_df.to_parquet(data_path.joinpath("package-analysis.parquet"), engine='pyarrow')


    # Read all Parquet files and find the union of all columns
    all_columns = set()
    dfs = []
    
    for file in parquet_files:
        pf = ParquetFile(file)
        df = pf.to_pandas()
        all_columns.update(df.columns)
        dfs.append(df)

    # Align schemas by reindexing all DataFrames
    all_columns = sorted(all_columns)  # Sort columns to maintain consistent order
    aligned_dfs = [df.reindex(columns=all_columns) for df in dfs]

    # Concatenate all DataFrames
    combined_par_df = pd.concat(aligned_dfs, ignore_index=True)
    
    # Save the combined DataFrame to a new Parquet file
    combined_par_df.to_parquet(data_path.joinpath("package-analysis.parquet"), index=False, engine='fastparquet')


if __name__=="__main__":
    # inte_csv()
    inte_parquets()