"""Build a labelled dataset from benign data and two local simulation rounds.

Only malicious coordinates recorded as local-archive runs in analysis_runs.csv
are admitted.  Package archives are never opened or executed by this module.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = PROJECT_ROOT / "data"
FEATURES = ("Files", "Sockets", "Commands", "DNS")
PHASES = ("import", "install")
FEATURE_COLUMNS = tuple(f"{phase}_{feature}" for phase in PHASES for feature in FEATURES)
BASE_COLUMNS = ("Ecosystem", "Version", "Name", *FEATURE_COLUMNS, "Label", "Sub_Label")
QUALITY_COLUMNS = (
    "Simulation_Source",
    "Analysis_Status",
    "Trace_Valid",
    "Timed_Out",
    "Local_Archive",
)


@dataclass(frozen=True)
class LocalRun:
    timestamp: str
    timed_out: bool
    archive: str


def normalize_ecosystem(value: Any) -> str:
    ecosystem = str(value or "").strip().lower()
    return {
        "python": "pypi",
        "ruby": "rubygems",
        "gem": "rubygems",
        "crates": "crates.io",
        "cratesio": "crates.io",
    }.get(ecosystem, ecosystem)


def normalize_name(ecosystem: str, value: Any) -> str:
    name = str(value or "").strip().casefold()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def coordinate(ecosystem: Any, name: Any, version: Any) -> tuple[str, str, str]:
    eco = normalize_ecosystem(ecosystem)
    return eco, normalize_name(eco, name), str(version or "").strip()


def read_local_runs(results_root: Path) -> dict[tuple[str, str, str], LocalRun]:
    """Return the latest local attempt for every coordinate in a run manifest."""
    manifest = results_root / "analysis_runs.csv"
    if not manifest.is_file():
        raise FileNotFoundError(f"missing run manifest: {manifest}")
    runs: dict[tuple[str, str, str], LocalRun] = {}
    with manifest.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required = {"ecosystem", "name", "version", "source", "local_archive", "timed_out"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"invalid run manifest: {manifest}")
        for row in reader:
            archive = (row.get("local_archive") or "").strip()
            if row.get("source") != "backstabbers" or not archive:
                continue
            key = coordinate(row["ecosystem"], row["name"], row["version"])
            current = LocalRun(
                timestamp=(row.get("timestamp_utc") or ""),
                timed_out=(row.get("timed_out") or "").lower() == "true",
                archive=archive,
            )
            if key not in runs or current.timestamp >= runs[key].timestamp:
                runs[key] = current
    return runs


def analysis_quality(analysis: Any) -> tuple[str, bool, int]:
    if not isinstance(analysis, dict):
        return "missing", False, 0
    statuses: list[str] = []
    populated = 0
    for phase in PHASES:
        value = analysis.get(phase)
        if not isinstance(value, dict):
            statuses.append("missing")
            continue
        statuses.append(str(value.get("Status") or "missing"))
        populated += sum(bool(value.get(feature)) for feature in FEATURES)
    if all(status == "completed" for status in statuses):
        status = "completed"
    elif "completed" in statuses:
        status = "partial_completed"
    elif "error_analysis" in statuses:
        status = "error_analysis"
    else:
        status = "+".join(statuses)
    return status, populated > 0, populated


def malicious_record(path: Path, run: LocalRun, source_name: str) -> tuple[dict[str, Any], int] | None:
    try:
        with path.open(encoding="utf-8") as source:
            report = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    package = report.get("Package")
    if not isinstance(package, dict):
        return None
    analysis = report.get("Analysis")
    status, trace_valid, populated = analysis_quality(analysis)
    row: dict[str, Any] = {
        "Ecosystem": normalize_ecosystem(package.get("Ecosystem")),
        "Version": str(package.get("Version") or ""),
        "Name": str(package.get("Name") or ""),
        "Label": 1,
        "Sub_Label": "",
        "Simulation_Source": source_name,
        "Analysis_Status": status,
        "Trace_Valid": trace_valid,
        "Timed_Out": run.timed_out,
        "Local_Archive": run.archive,
    }
    for phase in PHASES:
        phase_data = analysis.get(phase) if isinstance(analysis, dict) else None
        for feature in FEATURES:
            row[f"{phase}_{feature}"] = phase_data.get(feature, "") if isinstance(phase_data, dict) else ""
    # Prefer complete phases, then richer traces, then the newer file.
    completed = status == "completed"
    partial = status == "partial_completed"
    score = (
        int(completed) * 10**15
        + int(partial) * 5 * 10**14
        + populated * 10**12
        + int(path.stat().st_mtime)
    )
    return row, score


def load_malicious_round(results_root: Path, source_name: str) -> dict[tuple[str, str, str], tuple[dict[str, Any], int]]:
    runs = read_local_runs(results_root)
    selected: dict[tuple[str, str, str], tuple[dict[str, Any], int]] = {}
    results_dir = results_root / "results"
    for path in sorted(results_dir.glob("*.json")):
        parsed = malicious_record(path, LocalRun("", False, ""), source_name)
        if parsed is None:
            continue
        row, score = parsed
        key = coordinate(row["Ecosystem"], row["Name"], row["Version"])
        run = runs.get(key)
        if run is None:
            continue
        row["Timed_Out"] = run.timed_out
        row["Local_Archive"] = run.archive
        if key not in selected or score > selected[key][1]:
            selected[key] = row, score
    return selected


def apply_sub_labels(frame: Any, metrics_path: Path) -> Any:
    import pandas as pd

    metrics = pd.read_csv(metrics_path, dtype=str).fillna("")
    labels: dict[tuple[str, str, str], str] = {}
    name_labels: dict[tuple[str, str], str] = {}
    for row in metrics.to_dict("records"):
        key = coordinate(row.get("pkg_type"), row.get("name"), row.get("version"))
        if key[2]:
            labels[key] = row.get("attack_type", "")
        else:
            name_labels[key[:2]] = row.get("attack_type", "")
    frame["Sub_Label"] = [
        labels.get(coordinate(r.Ecosystem, r.Name, r.Version), name_labels.get(coordinate(r.Ecosystem, r.Name, "")[:2], ""))
        for r in frame.itertuples()
    ]
    return frame


def load_benign(parquet_root: Path) -> Any:
    from fea_ext_csv import CsvParser

    parser = CsvParser(parquet_root)
    frame = parser.fea_ext(parser.create_data())
    frame["Label"] = 0
    frame["Sub_Label"] = ""
    frame["Simulation_Source"] = "bigquery_benign"
    frame["Analysis_Status"] = "not_applicable"
    frame["Trace_Valid"] = True
    frame["Timed_Out"] = False
    frame["Local_Archive"] = ""
    return frame


def atomic_outputs(frame: Any, csv_path: Path, pickle_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=csv_path.parent, suffix=".csv", delete=False) as tmp:
        temp_csv = Path(tmp.name)
    with tempfile.NamedTemporaryFile(dir=pickle_path.parent, suffix=".pkl", delete=False) as tmp:
        temp_pickle = Path(tmp.name)
    try:
        frame.to_csv(temp_csv, index=False)
        frame.to_pickle(temp_pickle)
        os.replace(temp_csv, csv_path)
        os.replace(temp_pickle, pickle_path)
    finally:
        temp_csv.unlink(missing_ok=True)
        temp_pickle.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-root", type=Path, default=DATA_ROOT / "package-analysis-bigquery")
    parser.add_argument("--metrics", type=Path, default=DATA_ROOT.parent / "stas" / "data_metrics.csv")
    parser.add_argument(
        "--local-round",
        action="append",
        nargs=2,
        metavar=("NAME", "RESULTS_ROOT"),
        default=None,
        help="local simulation round; may be repeated",
    )
    parser.add_argument("--output", type=Path, default=DATA_ROOT / "label_data_v2.csv")
    parser.add_argument("--pickle-output", type=Path, default=DATA_ROOT / "label_data_v2.pkl")
    return parser.parse_args()


def main() -> int:
    import pandas as pd

    args = parse_args()
    rounds = args.local_round or [
        ("bkc_local", str(DATA_ROOT / "package-analysis-mal")),
        ("recovered_local", str(DATA_ROOT / "package-analysis-recovered-mal")),
    ]
    malicious: dict[tuple[str, str, str], tuple[dict[str, Any], int, int]] = {}
    for priority, (name, root_value) in enumerate(rounds):
        records = load_malicious_round(Path(root_value), name)
        print(f"{name}: admitted {len(records)} local coordinates")
        for key, (row, score) in records.items():
            candidate = row, score, priority
            current = malicious.get(key)
            if current is None or (priority, score) > (current[2], current[1]):
                malicious[key] = candidate

    mal_frame = pd.DataFrame([value[0] for value in malicious.values()])
    mal_frame = apply_sub_labels(mal_frame, args.metrics)
    benign = load_benign(args.benign_root)
    # Malicious evidence wins if a coordinate also occurs in the benign export.
    malicious_keys = set(malicious)
    benign_keys = [coordinate(r.Ecosystem, r.Name, r.Version) for r in benign.itertuples()]
    benign = benign[[key not in malicious_keys for key in benign_keys]]
    frame = pd.concat([benign, mal_frame], ignore_index=True)
    for column in (*BASE_COLUMNS, *QUALITY_COLUMNS):
        if column not in frame:
            frame[column] = ""
    frame = frame[[*BASE_COLUMNS, *QUALITY_COLUMNS]]
    atomic_outputs(frame, args.output, args.pickle_output)
    print(f"wrote {len(frame)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
