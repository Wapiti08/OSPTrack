'''
 # @ Create Time: 2024-07-29 09:28:03
 # @ Modified time: 2024-07-29 10:15:19
 # @ Description: connect with big query of package-analysis
 '''
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from google.cloud import bigquery
import os
import pandas as pd

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = \
                Path.cwd().parent.joinpath("session.json").as_posix()

def query_table(number, data_path):

    client = bigquery.Client()

    # define the query
    query = f"""
        SELECT *
        FROM `ossf-malware-analysis.packages.analysis`
        LIMIT {number}
    """

    # execute the query
    query_job = client.query(query)

    # # process the results
    # results = query_job.result()

    # # print the result
    # for row in results:
    #     print(row)

    # convert result to dataframe
    dataframe = query_job.to_dataframe()

    # save dataframe to csv and parquet
    csv_filename = "package-analysis.csv"
    parquet_filename = "package-analysis.parquet"
    dataframe.to_csv(Path(data_path).joinpath(csv_filename).as_posix(), index=False)
    dataframe.to_parquet(Path(data_path).joinpath(parquet_filename).as_posix(), index=False)


if __name__=="__main__":
    cur_path = Path.cwd().parent.joinpath("data")
    query_table(10000, cur_path)

