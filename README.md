# trigger_analyzer
trigger analyzer based in multi-source information fusion


## Modules

- Dynamic grpah construction


- Dynamic scoring


- Multiple Detection Logics


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
    sudo apt-get install docker.io

    # ------ macOS -------
    # docker desktop server
    brew install --cask docker
    # finish the configuration
    open -a Docker

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
