'''
 # @ Create Time: 2024-11-18 13:04:41
 # @ Modified time: 2024-11-18 13:04:48
 # @ Description: combine benign and malicious packages together to one label file

 '''

from fea_ext_csv import CsvParser
from fea_ext_json import JsonParser
import pandas as pd
from pathlib import Path


def main(mali_data_path, ben_data_path, metric_data_path, bkc_mal_file, save_path):
    # generate labelled malicious data
    csvparser = CsvParser(ben_data_path)
    par_data_list = csvparser.create_data()
    ben_csv_df = csvparser.fea_ext(par_data_list)
    label_csv_df = csvparser.label_match(ben_csv_df, bkc_mal_file)


    # generate labelled malicious data
    jsonparser = JsonParser(mali_data_path)
    json_data = jsonparser.create_data()
    report_df = jsonparser.fea_ext(json_data)
    mal_df = jsonparser.label_create(report_df)

    data_metric = pd.read_csv(metric_data_path)
    mal_df_labels = jsonparser.sub_label_create(mal_df, data_metric)

    total_df = pd.concat([label_csv_df, mal_df_labels], ignore_index=True)

    # Desired column order
    column_order = ['Ecosystem', 'Version', 'Name', 'import_Files', 'import_Sockets', 'import_Commands', 'import_DNS',
                    'install_Files', 'install_Sockets', 'install_Commands', 'install_DNS', 'Label', 'Sub_Label']

    # Reorder the DataFrame columns
    total_df = total_df[column_order]
    # save to csv
    total_df.to_csv(save_path.joinpath("label_data.csv"))
    # save to pickle format
    total_df.to_pickle(save_path.joinpath("label_data.pkl"))



if __name__ == "__main__":

    mali_data_path = Path.cwd().parent.joinpath("data","package-analysis-mal","results")
    metric_data_path = Path.cwd().parent.joinpath("data","stas", 'data_metrics.csv')
    ben_data_path = Path.cwd().parent.joinpath("data", "package-analysis-bigquery")

    bkc_mal_file = Path.cwd().parent.joinpath("data", "bkc_mal.csv")

    
    save_path = Path.cwd().parent.joinpath("data")
    main(mali_data_path, ben_data_path, metric_data_path, bkc_mal_file, save_path)