"""Batch package-analysis runner with local Backstabber sample resolution.

The package archives handled by this module are untrusted.  This module never
imports or extracts them; it only passes one archive at a time to the existing
package-analysis Docker/gVisor execution chain.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shlex
import signal
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_BKC_SAMPLES = DEFAULT_DATA_DIR / "Backstabbers-Knife-Collection" / "samples"
DEFAULT_RESULTS_ROOT = DEFAULT_DATA_DIR / "package-analysis-mal"
DEFAULT_SOURCE_CSV = DEFAULT_DATA_DIR / "pkg_mal.csv"
DEFAULT_RUN_SCRIPT = PROJECT_ROOT / "run_analysis.sh"

# These are the ecosystems supported by the package-analysis revision used by
# this project.  NuGet and Maven/JCenter samples must not be sent to it.
SUPPORTED_ECOSYSTEMS = {"npm", "pypi", "rubygems", "packagist", "crates.io"}
ARCHIVE_SUFFIXES = {
    "npm": (".tgz", ".tar.gz"),
    "pypi": (".tar.gz", ".whl", ".zip"),
    "rubygems": (".gem",),
    "packagist": (".zip",),
    "crates.io": (".crate",),
}
RESULT_ENV_VARS = {
    "RESULTS_DIR": "results",
    "STATIC_RESULTS_DIR": "staticResults",
    "FILE_WRITE_RESULTS_DIR": "writeResults",
    "ANALYZED_PACKAGES_DIR": "analyzedPackages",
    "LOGS_DIR": "logs",
    "STRACE_LOGS_DIR": "straceLogs",
}


@dataclass(frozen=True)
class PackageRef:
    ecosystem: str
    name: str
    version: str


@dataclass(frozen=True)
class RunResult:
    command: tuple[str, ...]
    returncode: int | None
    timed_out: bool = False


def normalize_ecosystem(ecosystem: str) -> str:
    value = ecosystem.strip().lower()
    aliases = {
        "python": "pypi",
        "ruby": "rubygems",
        "gem": "rubygems",
        "crates": "crates.io",
        "cratesio": "crates.io",
    }
    return aliases.get(value, value)


def normalize_package_name(ecosystem: str, name: str) -> str:
    """Normalize names only as allowed by the relevant package registry."""
    value = name.strip().casefold()
    if normalize_ecosystem(ecosystem) == "pypi":
        # PEP 503: runs of '-', '_' and '.' are equivalent in project names.
        return re.sub(r"[-_.]+", "-", value)
    return value


def package_key(package: PackageRef) -> tuple[str, str, str]:
    ecosystem = normalize_ecosystem(package.ecosystem)
    return ecosystem, normalize_package_name(ecosystem, package.name), package.version.strip()


def pack_info_load(file_name: str | Path) -> list[PackageRef]:
    """Load package coordinates without allowing CSV to coerce version strings."""
    path = Path(file_name)
    if path.suffix.lower() != ".csv":
        raise ValueError(f"package input must be CSV: {path}")

    packages: list[PackageRef] = []
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required = {"ecosystem", "name", "version"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"{path} must contain columns: {', '.join(sorted(required))}")
        for row in reader:
            ecosystem = normalize_ecosystem(row["ecosystem"] or "")
            name = (row["name"] or "").strip()
            version = (row["version"] or "").strip()
            if ecosystem and name:
                packages.append(PackageRef(ecosystem, name, version))
    return packages


def _is_archive(path: Path, ecosystem: str) -> bool:
    return any(path.name.lower().endswith(suffix) for suffix in ARCHIVE_SUFFIXES[ecosystem])


def _metadata_coordinates(metadata_path: Path, directory_version: str) -> set[tuple[str, str]]:
    """Read package name/version hints from BKC metadata, never from package code."""
    coordinates: set[tuple[str, str]] = set()
    if metadata_path.is_symlink() or not metadata_path.is_file():
        return coordinates
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return coordinates

    name = metadata.get("name")
    if isinstance(name, str):
        # The version directory and archive are authoritative.  Some BKC
        # metadata files were copied between adjacent version directories.
        coordinates.add((name, directory_version))

    versions = metadata.get("versions")
    if isinstance(versions, dict):
        version_metadata = versions.get(directory_version)
        if isinstance(version_metadata, dict) and isinstance(version_metadata.get("name"), str):
            coordinates.add((version_metadata["name"], directory_version))
    return coordinates


def _directory_name_aliases(ecosystem: str, directory_name: str) -> set[str]:
    aliases = {directory_name}
    if ecosystem == "npm":
        # BKC stores @scope/name as @scope_name because '/' cannot be part of a
        # single directory name.  Metadata remains the preferred source.
        if directory_name.startswith("@") and "_" in directory_name:
            scope, package = directory_name.split("_", 1)
            aliases.add(f"{scope}/{package}")
        # Some older BKC samples use scope__name without the leading '@'.
        if not directory_name.startswith("@") and "__" in directory_name:
            scope, package = directory_name.split("__", 1)
            aliases.add(f"@{scope}/{package}")
    return aliases


def _archive_preference(ecosystem: str, path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if ecosystem == "pypi":
        if name.endswith(".tar.gz"):
            return 0, name
        if name.endswith("py3-none-any.whl"):
            return 1, name
        if name.endswith("cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"):
            return 2, name
        if name.endswith(".whl"):
            return 3, name
        return 4, name
    if ecosystem == "mavencentral" and not name.endswith("-sources.jar"):
        return 0, name
    return 0, name


def build_local_package_index(samples_root: str | Path) -> dict[tuple[str, str, str], tuple[Path, ...]]:
    """Index BKC archives by exact ecosystem/name/version coordinates."""
    root = Path(samples_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Backstabber samples directory not found: {root}")
    index: defaultdict[tuple[str, str, str], set[Path]] = defaultdict(set)

    for ecosystem in sorted(SUPPORTED_ECOSYSTEMS):
        ecosystem_root = root / ecosystem
        if not ecosystem_root.is_dir():
            continue
        for archive in ecosystem_root.rglob("*"):
            if archive.is_symlink() or not archive.is_file() or not _is_archive(archive, ecosystem):
                continue
            try:
                archive.relative_to(ecosystem_root)
                resolved_archive = archive.resolve()
                resolved_archive.relative_to(root)
                version_dir = archive.parent
                package_dir = version_dir.parent
            except ValueError:
                continue

            coordinates = {
                (name, version_dir.name)
                for name in _directory_name_aliases(ecosystem, package_dir.name)
            }
            coordinates.update(_metadata_coordinates(version_dir / "metadata.json", version_dir.name))
            for name, version in coordinates:
                key = package_key(PackageRef(ecosystem, name, version))
                index[key].add(resolved_archive)

    return {
        key: tuple(sorted(paths, key=lambda path: _archive_preference(key[0], path)))
        for key, paths in index.items()
    }


def find_local_archive(
    package: PackageRef,
    index: dict[tuple[str, str, str], tuple[Path, ...]],
) -> Path | None:
    if not package.version:
        return None
    candidates = index.get(package_key(package), ())
    return candidates[0] if candidates else None


def sanitize_result_component(value: str) -> str:
    """Mirror run_analysis.sh's path-separator escaping."""
    return value.replace("/", "__").replace("\\", "__").replace("\n", "_").replace("\r", "_")


def result_prefix(package: PackageRef) -> str:
    return "-".join(
        sanitize_result_component(value)
        for value in (normalize_ecosystem(package.ecosystem), package.name, package.version)
    )


def _result_matches_package(result: dict, package: PackageRef) -> bool:
    actual = result.get("Package")
    if not isinstance(actual, dict):
        return False
    actual_ecosystem = normalize_ecosystem(str(actual.get("Ecosystem", "")))
    expected_ecosystem = normalize_ecosystem(package.ecosystem)
    if actual_ecosystem != expected_ecosystem:
        return False
    if normalize_package_name(expected_ecosystem, str(actual.get("Name", ""))) != normalize_package_name(
        expected_ecosystem, package.name
    ):
        return False
    return not package.version or str(actual.get("Version", "")) == package.version


def _result_has_completed_phase(result: dict) -> bool:
    analysis = result.get("Analysis")
    if not isinstance(analysis, dict):
        return False
    return any(
        isinstance(phase, dict) and phase.get("Status") == "completed"
        for phase in analysis.values()
    )


def is_analyzed(package: PackageRef, result_dir: str | Path) -> bool:
    """Return true only for a correctly named result with a completed phase.

    Older versions of run_analysis.sh could rename a previous package's JSON
    to the current package's filename.  Checking the embedded Package object
    prevents those corrupted names, and registry install errors, from causing
    a local BKC rerun to be skipped.
    """
    directory = Path(result_dir)
    prefix = result_prefix(package)
    try:
        directory_entries = list(directory.iterdir())
    except OSError:
        return False
    candidates = [
        candidate
        for candidate in directory_entries
        if candidate.name == f"{prefix}.json"
        or (candidate.name.startswith(f"{prefix}.") and candidate.name.endswith(".json"))
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            result = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if _result_matches_package(result, package) and _result_has_completed_phase(result):
            return True
    return False


def build_analysis_command(
    script_path: str | Path,
    package: PackageRef,
    local_archive: Path | None = None,
    offline: bool = False,
    fully_offline: bool = False,
    dry_run_wrapper: bool = False,
) -> list[str]:
    command = [str(Path(script_path).resolve()), "-nointeractive"]
    if dry_run_wrapper:
        command.append("-dryrun")
    if fully_offline:
        command.extend(("-fully-offline", "-offline", "-nopull"))
    elif offline:
        command.append("-offline")
    command.extend(("-ecosystem", package.ecosystem, "-package", package.name))
    if package.version:
        command.extend(("-version", package.version))
    if local_archive is not None:
        command.extend(("-local", str(local_archive.resolve())))
    return command


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run_analysis(
    command: Sequence[str],
    environment: dict[str, str],
    timeout_seconds: int,
    dry_run: bool = False,
) -> RunResult:
    LOGGER.info("analysis command: %s", shlex.join(command))
    if dry_run:
        return RunResult(tuple(command), None)

    process = subprocess.Popen(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process)
        stdout, stderr = process.communicate()
        LOGGER.warning("analysis timed out after %s seconds", timeout_seconds)
        if stdout:
            LOGGER.debug("analysis stdout:\n%s", stdout[-8000:])
        if stderr:
            LOGGER.warning("analysis stderr:\n%s", stderr[-8000:])
        return RunResult(tuple(command), process.returncode, timed_out=True)

    if stdout:
        LOGGER.debug("analysis stdout:\n%s", stdout[-8000:])
    if stderr:
        LOGGER.debug("analysis stderr:\n%s", stderr[-8000:])
    return RunResult(tuple(command), process.returncode)


def result_environment(results_root: str | Path, create: bool = True) -> dict[str, str]:
    environment = os.environ.copy()
    root = Path(results_root).resolve()
    for variable, subdirectory in RESULT_ENV_VARS.items():
        path = root / subdirectory
        if create:
            path.mkdir(parents=True, exist_ok=True)
        environment[variable] = str(path)
    return environment


def append_run_manifest(
    manifest_path: Path,
    package: PackageRef,
    source: str,
    archive: Path | None,
    result: RunResult,
) -> None:
    new_file = not manifest_path.exists()
    with manifest_path.open("a", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=(
                "timestamp_utc",
                "ecosystem",
                "name",
                "version",
                "source",
                "local_archive",
                "returncode",
                "timed_out",
            ),
        )
        if new_file:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "ecosystem": package.ecosystem,
                "name": package.name,
                "version": package.version,
                "source": source,
                "local_archive": str(archive) if archive else "",
                "returncode": "" if result.returncode is None else result.returncode,
                "timed_out": result.timed_out,
            }
        )


def configure_logging(log_path: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run package-analysis, preferring exact local BKC samples over registry downloads."
    )
    parser.add_argument("--source-csv", type=Path, default=DEFAULT_SOURCE_CSV)
    parser.add_argument("--bkc-samples", type=Path, default=DEFAULT_BKC_SAMPLES)
    parser.add_argument("--script", type=Path, default=DEFAULT_RUN_SCRIPT)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument(
        "--mode",
        choices=("local-first", "local-only", "remote-only"),
        default="local-only",
        help="local-first uses an exact BKC match and falls back to the registry",
    )
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--limit", type=int, help="maximum number of CSV rows to inspect")
    parser.add_argument("--timeout", type=int, default=600, help="per-package timeout in seconds")
    parser.add_argument("--rerun", action="store_true", help="run even if a valid completed result exists")
    parser.add_argument("--dry-run", action="store_true", help="print commands without starting Docker")
    parser.add_argument("--offline", action="store_true", help="disable network in the inner gVisor sandbox")
    parser.add_argument(
        "--fully-offline",
        action="store_true",
        help="also disable the outer analysis container network; requires cached images and local-only mode",
    )
    return parser.parse_args(argv)


def package_slice(packages: Sequence[PackageRef], start: int, limit: int | None) -> Iterable[PackageRef]:
    if start < 0:
        raise ValueError("--start-index must be non-negative")
    selected = packages[start:]
    return selected if limit is None else selected[:limit]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.fully_offline and args.mode != "local-only":
        raise SystemExit("--fully-offline requires --mode local-only")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    if args.timeout < 1:
        raise SystemExit("--timeout must be positive")
    if not args.script.is_file() or not os.access(args.script, os.X_OK):
        raise SystemExit(f"analysis script is missing or not executable: {args.script}")

    configure_logging(None if args.dry_run else args.results_root / "simu_run.log")
    packages = pack_info_load(args.source_csv)
    local_index = build_local_package_index(args.bkc_samples) if args.mode != "remote-only" else {}
    LOGGER.info(
        "loaded %d package rows and %d exact local package coordinates",
        len(packages),
        len(local_index),
    )

    environment = result_environment(args.results_root, create=not args.dry_run)
    results_dir = args.results_root / RESULT_ENV_VARS["RESULTS_DIR"]
    manifest_path = args.results_root / "analysis_runs.csv"
    counters = defaultdict(int)
    warned_ecosystems: set[str] = set()

    for package in package_slice(packages, args.start_index, args.limit):
        counters["inspected"] += 1
        if package.ecosystem not in SUPPORTED_ECOSYSTEMS:
            counters["unsupported"] += 1
            if package.ecosystem not in warned_ecosystems:
                LOGGER.warning("skipping unsupported ecosystem: %s", package.ecosystem)
                warned_ecosystems.add(package.ecosystem)
            continue

        local_archive = None
        if args.mode != "remote-only":
            local_archive = find_local_archive(package, local_index)
        if args.mode == "local-only" and local_archive is None:
            counters["no_local_match"] += 1
            continue

        if not args.rerun and is_analyzed(package, results_dir):
            counters["already_completed"] += 1
            continue

        source = "backstabbers" if local_archive is not None else "registry"
        command = build_analysis_command(
            args.script,
            package,
            local_archive=local_archive,
            offline=args.offline,
            fully_offline=args.fully_offline,
        )
        LOGGER.info(
            "running %s/%s@%s from %s%s",
            package.ecosystem,
            package.name,
            package.version or "latest",
            source,
            f" ({local_archive})" if local_archive else "",
        )
        result = run_analysis(command, environment, args.timeout, dry_run=args.dry_run)
        counters[f"source_{source}"] += 1
        if args.dry_run:
            counters["planned"] += 1
        elif result.returncode == 0:
            counters["succeeded"] += 1
        else:
            counters["failed"] += 1
            LOGGER.warning(
                "analysis failed for %s/%s@%s (exit=%s)",
                package.ecosystem,
                package.name,
                package.version,
                result.returncode,
            )
        if not args.dry_run:
            append_run_manifest(manifest_path, package, source, local_archive, result)

    LOGGER.info("run summary: %s", dict(sorted(counters.items())))
    return 1 if counters["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
