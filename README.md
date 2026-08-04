# OSPTrack
labelled dataset for simulated package execution with package-analysis

**This work has been accepted at MSR 2025 Data and Tool Showcase Track, will present on 28th, April, 2025**

![Python](https://img.shields.io/badge/Python3-3.10-brightgreen.svg) 
![License](https://img.shields.io/badge/license-MIT3.0-green.svg)
![Testing Environment](https://img.shields.io/badge/Ubuntu-22.04.5-golden.svg)
[![DOI](https://zenodo.org/badge/677001279.svg)](https://doi.org/10.5281/zenodo.14197321)


## Structure (core)

- ana:

    - stastical analysis for [BKC Dataset](https://dasfreak.github.io/Backstabbers-Knife-Collection/) and also [malicious-packages](https://github.com/ossf/malicious-packages/tree/main/osv/malicious)

    - the code to extract metrics.csv and iocs.csv files
    
    - label distribution analysis for labeled dataset

- data:

    - collection from BKC and also malicious-packages

    - places to save bkc_mal.csv and pkg_mal.csv

    - places to save extracted data also final labeled dataset

- data_create:

    - code to query BigQuery

    - code to run simulation

- ext:

    - code to parse reports (json and csv) 
    
    - code to extract features and generate final dataset

- run_analysis.sh:

    custom shell script to run package-analysis to save results locally and avoid repetitions


## Preparation (Environment Setting Up)

- For BigQuqry:
```
# download bigquery key from google cloud
# activate the key
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account-file.json"
# the key needs to be loaded when querying BigQuery

```

- For running [Package-Analysis](https://github.com/ossf/package-analysis) (only feasible on Ubuntu)

```
# git download
sudo apt-get install git
# docker
sudo apt-get install -y docker.io
# start the docker service
sudo systemctl start docker
# golang download
sudo apt-get install golang

# direct running --- check whether this tool works locally
# how to run local instance
## local instance
scripts/run_analysis.sh -ecosystem pypi -package test -local /path/to/test.whl
## live instance
scripts/run_analysis.sh -ecosystem pypi -package Django -version 4.1.3


## after successfully running one instance
## replace the run_analysis.sh with the one provided in this resp --- give 755 
```


## Running Instructions

```
# virtual environment setting up
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

## query data from BigQuery
python3 data_bigquery.py

# run simulation by calling package-analysis
sudo python3 simu_run.py

```

## Replaying local Backstabber samples

`data_create/simu_run.py` indexes archive files under
`data/Backstabbers-Knife-Collection/samples` by ecosystem, normalized package
name, and exact version. Its default `local-only` mode passes exact matches to
package-analysis with `-local` and skips unmatched coordinates. The optional
`local-first` mode falls back to the live registry. Maven/JCenter and NuGet are
skipped because the package-analysis revision used here does not support them.

Review the matches and commands without starting Docker:

```bash
python3 data_create/simu_run.py --mode local-only --dry-run --limit 100
```

Run only exact local matches (recommended for replacing unavailable registry
packages):

```bash
sudo python3 data_create/simu_run.py --mode local-only
```

Prefer local matches but retain registry fallback:

```bash
sudo python3 data_create/simu_run.py --mode local-first
```

Useful controls are `--start-index`, `--limit`, `--timeout`, and `--rerun`.
Use `--offline` to disable network access in the inner gVisor sandbox. Use
`--fully-offline` only with `--mode local-only` and when both outer and nested
container images have already been cached.

The batch runner treats a prior result as complete only when its embedded
package coordinate matches the requested package and at least one dynamic phase
has status `completed`. This allows old registry-download failures to be
replayed from BKC. Each attempted run is recorded in
`data/package-analysis-mal/analysis_runs.csv`, including whether the source was
`backstabbers` or `registry`.

Malicious packages are mounted read-only into the trusted outer analysis image
and executed only in package-analysis's nested gVisor container. Run this on a
dedicated analysis host with no production credentials. Omitting `--offline`
allows public-network egress from the sandbox (private ranges are firewalled) so
that DNS/socket behavior can be captured; choose that tradeoff deliberately.
