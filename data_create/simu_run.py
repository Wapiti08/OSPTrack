'''
 # @ Create Time: 2024-10-23 09:57:52
 # @ Modified time: 2024-10-23 09:58:25
 # @ Description: the module to simulate the execution of malicious packages based on 
 package name and version in provided csv files
 '''

import pandas as pd
import os
import subprocess
from pathlib import Path
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('simu_run.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)



def pack_info_load(file_name):
    '''
    :param file_name: the csv file saving basic info regarding released malicious package
    '''
    if not file_name.endswith(".csv"):
        exit
    
    return pd.read_csv(file_name)



def simu_live_cmd(script_path, eco, pack, version):
    ''' simulate the execution of package based on give name and version number
    
    '''
    if not isinstance(version, float):
        command = f"sh {script_path} -ecosystem {eco} -package {pack} -version {version}"
                
    else:
        command = f"sh {script_path} -ecosystem {eco} -package {pack}"

    try:
        # run the command
        result = subprocess.run(command,shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info(f"successfully analysed {eco}-{pack}-{version}")
        else:
            logger.info(f"failed to analyse {eco}-{pack}-{version}")
    
    except subprocess.CalledProcessError as e:
        logger.info("Error:", e.stderr)
    
    except FileNotFoundError as e:
        logger.info("File not foun: d", e)

    finally:
        pass

def simu_local_cmd(script_path, eco, pack, path):
    ''' simulate the execution of package based on local packages
    
    '''
    command = f"sh {script_path} -ecosystem {eco} -package {pack} -local {path}"

    try:
        # run the command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            output = result.stdout
            logger.info("Command Output:", output)
            logger.info(f"successfully analysed {eco}-{pack} at {path}")
        else:
            logger.info(f"failed to analyse {eco}-{pack} at {path}")

    except subprocess.CalledProcessError as e:
        logger.info("Error:", e.stderr)
    
    except FileNotFoundError as e:
        logger.info("File not found:", e)

    finally:
        pass

if __name__ == "__main__":
    # define the path to save simulated result
    data_path = Path.cwd().parent.joinpath("data","package-analysis-mal")
    
    # set the enviroment variables for custom directories
    os.environ["RESULTS_DIR"] = data_path.joinpath("results").as_posix()
    os.environ["STATIC_RESULTS_DIR"] = data_path.joinpath("staticResults").as_posix()
    os.environ["FILE_WRITE_RESULTS_DIR"] = data_path.joinpath("writeResults").as_posix()
    os.environ["ANALYZED_PACKAGES_DIR"] = data_path.joinpath("analyzedPackages").as_posix()
    os.environ["LOGS_DIR"] = data_path.joinpath("logs").as_posix()
    os.environ["STRACE_LOGS_DIR"] = data_path.joinpath("straceLogs").as_posix()

    # define the packages info file
    pkg_mal_file = Path.cwd().parent.joinpath("data", "pkg_mal.csv").as_posix()
    bkc_mal_file = Path.cwd().parent.joinpath("data", "bkc_mal.csv").as_posix()

    bkc_df = pack_info_load(pkg_mal_file)
    pkg_df = pack_info_load(bkc_mal_file)

    # define script path
    script_path = Path.cwd().parent.parent.joinpath("package-analysis", "scripts", "run_analysis.sh").as_posix()

    # run script to simulate
    for index, row in bkc_df.iterrows():
        simu_live_cmd(script_path, row["ecosystem"].lower(), row["name"], row["version"])

