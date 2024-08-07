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
from tqdm import tqdm

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = \
                Path.cwd().parent.joinpath("session.json").as_posix()

def query_table(number, offset, data_path):

    client = bigquery.Client()
    chunk_size = 500

    for order in tqdm(range(offset, number-chunk_size, chunk_size), total=number/chunk_size, desc="generating chunks of data"):
        chunk_number = order + chunk_size
        print("current chunk offset is:", order)
        # define the query
        query = f"""
            SELECT *
            FROM `ossf-malware-analysis.packages.analysis`
            LIMIT {chunk_size}
            OFFSET {order}
        """

        # execute the query
        query_job = client.query(query)

        # # process the results
        results = query_job.result()

        # # print the result
        # for row in results:
        #     print(row)

        # set the chunk size to avoid excess problem
        # page_size = 10
        # index = 0
        # # Iterate through results in chunks of 100
        # total_chunks = (number + page_size - 1) // page_size

        # acc_rows = []

        # for page in tqdm(query_job.result(page_size=page_size).pages, total=number,
        #                  desc="saving results with chunks"):
        #     # print(query_job.state)
        #     # print(page)
        #     rows = list([list(row) for row in page])
        #     acc_rows.extend(rows)
        #     if len(acc_rows) == 500:
        #         chunk_df = pd.DataFrame(acc_rows, columns = ["Package","CreatedTimestamp","Analysis"])
        #         index += 1
        #         csv_filename = f"package-analysis-{index}.csv"
        #         parquet_filename = f"package-analysis-{index}.parquet"
        #         chunk_df.to_csv(Path(data_path).joinpath(csv_filename).as_posix(), index=False)
        #         chunk_df.to_parquet(Path(data_path).joinpath(parquet_filename).as_posix(), index=False)
        #         acc_rows = []
        #     else:
        #         continue
        chunk_df = results.to_dataframe()
        csv_filename = f"package-analysis-{chunk_number}.csv"
        parquet_filename = f"package-analysis-{chunk_number}.parquet"
        chunk_df.to_csv(Path(data_path).joinpath(csv_filename).as_posix(), index=False)
        chunk_df.to_parquet(Path(data_path).joinpath(parquet_filename).as_posix(), index=False)


if __name__=="__main__":
    cur_path = Path.cwd().parent.joinpath("data")
    query_table(10000, 500, cur_path)

