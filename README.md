# OSPTrack
labelled dataset for simulated package execution with package-analysis

## Modules

- data query

- data match

- package simulation

- data filtering

- feature extraction

- graph representation


## Preparation
```
# download bigquery key from google cloud
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account-file.json"
```



## Usage Record

- [Package-Analysis](https://github.com/ossf/package-analysis)
    - required environment (Ubuntu and macOS)
    ```
    # ------ Ubuntu ------ Recommended System to Run......
    # git
    sudo apt-get install git
    # docker
    sudo apt-get install -y docker.io
    # start the docker service
    sudo systemctl start docker

    # direct running 
    # how to run local instance
    ## local instance
    scripts/run_analysis.sh -ecosystem pypi -package test -local /path/to/test.whl
    ## live instance
    scripts/run_analysis.sh -ecosystem pypi -package Django -version 4.1.3
    ```

- findings：
    - Command (key)
        - lsb, version, providers  --- check potential system type, version for suitable exploitation 
    - DNS (key)
        - hostname -- malicious or not
        - types --- txt, cname, ptr etc ---- further logic check 

- how to compare the differences
    - diff file1, file2

- ideas / thoughts:
    - through the differential analysis:
        - command --- as the string features? --- machine learning
        - features ---- give weights ---- part of risky score


## Running Instructions
```
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
```
