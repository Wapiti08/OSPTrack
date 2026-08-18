# OSPTrack
A labelled dataset for simulated package execution with package-analysis.

**This work was presented at the MSR 2025 Data and Tool Showcase Track and is
now published in the IEEE/ACM MSR 2025 proceedings (pp. 659--663). Read the
[paper on IEEE Xplore](https://ieeexplore.ieee.org/document/11025755) or use
[DOI 10.1109/MSR66628.2025.00102](https://doi.org/10.1109/MSR66628.2025.00102).**

![Python](https://img.shields.io/badge/Python3-3.10-brightgreen.svg) 
![License](https://img.shields.io/badge/license-MIT3.0-green.svg)
![Testing Environment](https://img.shields.io/badge/Ubuntu-22.04_x86__64-golden.svg)
[![DOI](https://zenodo.org/badge/677001279.svg)](https://doi.org/10.5281/zenodo.21853840)


## Dataset snapshots and statistics

The snapshots should not be treated as interchangeable:

| Snapshot | Date/scope | Total reports | Benign | Malicious |
| --- | --- | ---: | ---: | ---: |
| Published paper | OpenSSF reference data through November 2024 | 9,461 | 7,499 | 1,962 |
| [Zenodo v4](https://doi.org/10.5281/zenodo.14680781) | Released 17 January 2025; historical source scope through November 2024 | 9,758 | 7,499 | 2,259 |
| Current strict local-archive rebuild (`label_data_v2.csv`) | Rebuilt 8 August 2026 from archived samples | 9,652 | 7,500 | 2,152 |

The August 2026 date is the **rebuild date**, not a claim that the source
catalogue covers packages published through August 2026. The latest documented
source/reference cutoff remains **November 2024**. The current rebuild only
admits malicious coordinates backed by an exact local archive and contains
2,152 malicious reports (22.30% of the dataset).

For those 2,152 malicious reports, an event record is one item in any of the
eight runtime feature lists (`Files`, `Sockets`, `Commands`, and `DNS` for both
the import and install phases). Empty lists count as zero. Together, the
malicious reports contain 8,698,912 observed event records: a mean of **4,042.25
records per malicious report** and a median of **2,634.5**.

| Event type | Mean records per malicious report (import + install) |
| --- | ---: |
| Files | 4,017.73 |
| Sockets | 7.88 |
| Commands | 15.89 |
| DNS | 0.75 |
| **All event types** | **4,042.25** |

These are observed sandbox records, not counts of distinct malicious actions.
Of the malicious reports, 829 completed both phases, 3 completed one phase, and
1,320 ended with `error_analysis` after still producing usable trace evidence.


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

Dynamic replay is tested on a dedicated Ubuntu 22.04 x86_64 analysis host or
virtual machine. macOS is not supported for this workflow because
package-analysis starts Podman and a nested gVisor sandbox inside Docker. Do not
use a workstation containing credentials, mounted home directories, or access
to production networks.

- For BigQuqry:
```
# download bigquery key from google cloud
# activate the key
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/service-account-file.json"
# the key needs to be loaded when querying BigQuery

```

- For running [Package-Analysis](https://github.com/ossf/package-analysis)

```bash
sudo apt-get update
sudo apt-get install -y docker.io git golang jq
sudo systemctl enable --now docker

# Confirm that Docker works before starting package analysis.
sudo docker run --rm hello-world

# Direct package-analysis smoke tests:
./run_analysis.sh -ecosystem pypi -package test -local /path/to/test.whl
./run_analysis.sh -ecosystem pypi -package Django -version 4.1.3
```

The supplied `run_analysis.sh` must remain executable (`chmod 755
run_analysis.sh`). Docker's `--privileged` mode is required by the trusted outer
analysis container so it can start the nested Podman/gVisor sandbox. Untrusted
package archives are mounted read-only and are executed only inside that nested
sandbox.


## Running Instructions

```
# virtual environment setting up
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

## query data from BigQuery
python3 data_bigquery.py

# run simulation by calling package-analysis
sudo python3 data_create/simu_run.py --mode local-only --timeout 900

```

## Replaying local Backstabber samples

`data_create/simu_run.py` indexes archive files under
`data/Backstabbers-Knife-Collection/samples` by ecosystem, normalized package
name, and exact version. Its default `local-only` mode passes exact matches to
package-analysis with `-local` and skips unmatched coordinates. The optional
`local-first` mode falls back to the live registry. Maven/JCenter and NuGet are
skipped because the package-analysis revision used here does not support them.

First review one exact match and its generated command without starting Docker:

```bash
python3 data_create/simu_run.py \
  --mode local-only \
  --dry-run \
  --start-index 1 \
  --limit 1
```

Run one exact local match without inner-sandbox network access:

```bash
sudo python3 data_create/simu_run.py \
  --mode local-only \
  --start-index 1 \
  --limit 1 \
  --timeout 900 \
  --offline
```

`--offline` still records file, process, socket, and syscall attempts, but it
cannot observe real DNS or remote connections and dependency downloads may
fail. After validating the offline run, repeat the sample with controlled
public-network access when network behavior is required:

```bash
sudo python3 data_create/simu_run.py \
  --mode local-only \
  --start-index 1 \
  --limit 1 \
  --timeout 900
```

Only remove `--offline` on a dedicated, credential-free host with controlled
egress. package-analysis blocks private address ranges, but an external proxy,
DNS sinkhole, or firewall allowlist is recommended as an additional boundary.

Run all exact local matches after validating both single-package runs:

```bash
sudo python3 data_create/simu_run.py \
  --mode local-only \
  --timeout 900
```

Monitor progress in another terminal:

```bash
tail -f data/package-analysis-mal/simu_run.log
```

The command is append-only: it does not replace old result files or log
directories. Name collisions receive sequence suffixes such as `.2` and `.3`,
while `analysis_runs.csv` and `simu_run.log` are appended. Interrupting the run
with Ctrl-C and executing the same command resumes the batch. A matching result
with at least one `completed` phase is skipped; `--rerun` deliberately disables
that skip behavior.

Useful controls are `--start-index`, `--limit`, `--timeout`, and `--rerun`.
Use `--offline` to disable network access in the inner gVisor sandbox. Use
`--fully-offline` only with `--mode local-only` and when both outer and nested
container images have already been cached. `--mode local-first` permits live
registry fallback and should not be used when the experiment must be restricted
to archived BKC specimens.

The batch runner treats a prior result as complete only when its embedded
package coordinate matches the requested package and at least one dynamic phase
has status `completed`. This allows old registry-download failures to be
replayed from BKC. Each attempted run is recorded in
`data/package-analysis-mal/analysis_runs.csv`, including whether the source was
`backstabbers` or `registry`.

### Results and partial-behavior interpretation

Outputs are stored below `data/package-analysis-mal/`:

- `results/`: dynamic JSON containing Files, Sockets, Commands, and DNS events
- `writeResults/`: file-write behavior
- `straceLogs/`: exported syscall logs, when produced by the analyzer
- `staticResults/`: static-analysis output
- `logs/`: complete sandbox diagnostics, including gVisor `runsc.log.boot`
- `analysis_runs.csv`: source archive, version, wrapper return code, and timeout
  state for every attempt

Inspect a dynamic result with:

```bash
jq '{
  package: .Package,
  phases: (.Analysis | with_entries(.value = .value.Status)),
  install_dns: .Analysis.install.DNS,
  install_sockets: .Analysis.install.Sockets,
  install_commands: .Analysis.install.Commands
}' data/package-analysis-mal/results/pypi-zproxy-1.0.json
```

## Rebuild the labelled dataset from both local simulation rounds

After both local-archive rounds have finished, build a new dataset without
overwriting the existing `label_data.csv`:

```bash
python3 ext/build_label_data.py \
  --local-round bkc_local data/package-analysis-mal \
  --local-round recovered_local data/package-analysis-recovered-mal \
  --output data/label_data_v2.csv \
  --pickle-output data/label_data_v2.pkl
```

The builder admits malicious coordinates only when the corresponding
`analysis_runs.csv` row records `source=backstabbers` and a non-empty local
archive path. It combines the original BKC local run and the recovered-archive
local run, deduplicates by normalized ecosystem/name/exact version, and gives
the recovered run priority for overlapping coordinates. The output retains
benign rows and adds `Simulation_Source`, `Analysis_Status`, `Trace_Valid`,
`Timed_Out`, and `Local_Archive` columns so partial traces are not confused
with fully completed analyses. Review `label_data_v2.csv` before replacing the
original labelled dataset.

An `error_analysis` result is not equivalent to an empty or useless result.
Malformed packages and platform-specific malware can execute setup code before
installation fails, leaving useful file, command, DNS, socket, and gVisor
syscall evidence. For example, the Linux `zproxy@1.0` trace shows creation of a
temporary Python downloader and an attempted Windows `start` command, but not
execution of the remote second stage. Report such evidence as **partial or
attempted behavior**, not as observed second-stage execution.

Conversely, `completed` means the analyzer completed at least one recorded
dynamic phase; it does not prove that every intended payload path ran or that
platform-specific behavior was reached. The current resume policy retries
`error_analysis` packages because only `completed` results are skipped. Avoid
restarting an interrupted batch without accounting for this behavior if failed
compatibility cases are already sufficient for the experiment.

Malicious packages are mounted read-only into the trusted outer analysis image
and executed only in package-analysis's nested gVisor container. Run this on a
dedicated analysis host with no production credentials. Omitting `--offline`
allows public-network egress from the sandbox (private ranges are firewalled) so
that DNS/socket behavior can be captured; choose that tradeoff deliberately.
