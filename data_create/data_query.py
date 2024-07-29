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

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = \
                Path.cwd().parent.joinpath("malicious-package-analysis-06cc8a92b5ff.json").as_posix()

def query_table():

    client = bigquery.Client()

    # define the query
    query = """
        SELECT *
        FROM `ossf-malware-analysis.packages.analysis`
        LIMIT 10
    """

    # execute the query
    query_job = client.query(query)

    # process the results
    results = query_job.result()

    # print the result
    for row in results:
        print(row)


if __name__=="__main__":
    query_table()

