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
from dotenv import load_dotenv
import time
from datetime import datetime
import threading

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

# load environment
load_dotenv()

# load password
sudo_pwd = os.getenv("SUDO")

def pack_info_load(file_name):
    '''
    :param file_name: the csv file saving basic info regarding released malicious package
    '''
    if not file_name.endswith(".csv"):
        exit
    
    return pd.read_csv(file_name)



def simu_live_cmd(script_path, eco, pack, version, check_interval=5, timeout_duration=600):
    ''' simulate the execution of package based on give name and version number
    
    '''
    if not isinstance(version, float):
        command = f"{script_path} -ecosystem {eco} -package {pack} -version {version}"
                
    else:
        command = f"{script_path} -ecosystem {eco} -package {pack}"

    try:
        if sudo_pwd:
            # run the command
            process = subprocess.Popen(command, shell=True, \
                                    stdout=subprocess.PIPE, stderr = subprocess.PIPE, \
                                    text=True)
            
            def terminate_process():
                ''' function to terminate the process if it exceeds the timeout
                
                '''
                if process.poll() is None:
                    process.terminate()
                    logger.warning(f"Process timed out for {eco}-{pack}-{version}")
                    logger.info(f"Timeout occured while analysing {eco}-{pack}-{version}")

            timer = threading.Timer(timeout_duration, terminate_process)
            timer.start()

            while True:
                # check if the process has terminated
                poll = process.poll()

                if poll is not None:
                    stdout, stderr = process.communicate(f'{sudo_pwd}\n')
                    if poll == 0:
                        logger.info(f"successfully analysed {eco}-{pack}-{version}")
                    else:
                        logger.info(f"failed to analyse {eco}-{pack}-{version}")
                    break
                
                # wait for a short interval before checking again
                logger.info("process is still running...")
                time.sleep(check_interval)

            # stop the timer if the process completes within the timeout
            timer.cancel()
        else:
            logger.error("sudo password not set")
        
    except subprocess.CalledProcessError as e:
        logger.info("Error:", e.stderr)
    
    except FileNotFoundError as e:
        logger.info("File not foun: d", e)

    finally:
        pass


def get_result_file(eco, pack, version, result_dir):
    return Path(result_dir).joinpath(f"{eco}-{pack}-{version}*")


def is_analyzed(eco, pack, version, result_dir):
    ''' check if a folder exists for the given package

    '''
    folder_pattern = get_result_file(eco, pack, version, result_dir)
    return any(folder_pattern.parent.glob(folder_pattern.name))



def simu_local_cmd(script_path, eco, pack, path):
    ''' simulate the execution of package based on local packages
    
    '''
    command = f"sudo {script_path} -ecosystem {eco} -package {pack} -local {path}"

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
        eco, pack, version = row["ecosystem"].lower(), row["name"], row["version"]
        # check whether this package has been analyzed
        if is_analyzed(eco, pack, version, data_path.joinpath("results")):
            logger.info(f"skipping already analyzed package: {eco}-{pack}-{version}")
            continue
        # run simulation
        simu_live_cmd(script_path, eco, pack, version)

