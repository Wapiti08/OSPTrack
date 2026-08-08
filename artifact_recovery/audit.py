#!/usr/bin/env python3
"""Read-only audit for recoverable malicious-package artifacts.

This tool deliberately does not download archives or execute package content.
All network checks are optional metadata probes.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "outputs"
ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".whl", ".zip", ".crate", ".gem")
REGISTRY_HOSTS = {
    "npm": "npmjs.org",
    "pypi": "pypi.org",
    "rubygems": "rubygems.org",
    "crates.io": "crates.io",
    "nuget": "nuget.org",
}


@dataclass(frozen=True, order=True)
class Coordinate:
    ecosystem: str
    name: str
    version: str


def normalize_ecosystem(value: str) -> str:
    aliases = {
        "python": "pypi",
        "ruby": "rubygems",
        "gem": "rubygems",
        "crates": "crates.io",
        "cratesio": "crates.io",
    }
    normalized = value.strip().lower()
    return aliases.get(normalized, normalized)


def normalize_name(ecosystem: str, value: str) -> str:
    normalized = value.strip().casefold()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", normalized)
    return normalized


def coordinate_key(coordinate: Coordinate) -> tuple[str, str, str]:
    return (
        coordinate.ecosystem,
        normalize_name(coordinate.ecosystem, coordinate.name),
        coordinate.version,
    )


def load_coordinates(path: Path) -> list[Coordinate]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required = {"ecosystem", "name", "version"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"{path} must contain ecosystem,name,version")
        result = []
        for row in reader:
            ecosystem = normalize_ecosystem(row["ecosystem"] or "")
            name = (row["name"] or "").strip()
            version = (row["version"] or "").strip()
            if ecosystem and name:
                result.append(Coordinate(ecosystem, name, version))
        return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_coordinate(data: dict, fallback_ecosystem: str = "") -> Coordinate | None:
    name = data.get("name") or data.get("Name")
    version = data.get("version") or data.get("Version")
    ecosystem = data.get("ecosystem") or data.get("Ecosystem") or fallback_ecosystem
    if name and version and ecosystem:
        return Coordinate(normalize_ecosystem(str(ecosystem)), str(name), str(version))
    return None


def inspect_archive(path: Path, hinted_ecosystem: str = "") -> Coordinate | None:
    """Read package metadata without extracting or importing the archive."""
    lower = path.name.lower()
    try:
        if lower.endswith(".gem"):
            with tarfile.open(path, "r:") as archive:
                member = archive.getmember("metadata.gz")
                stream = archive.extractfile(member)
                if stream:
                    return parse_rubygems_metadata(gzip.decompress(stream.read()).decode("utf-8", "replace"))
        if lower.endswith((".tgz", ".tar.gz", ".crate")):
            with tarfile.open(path, "r:*") as archive:
                members = [member for member in archive.getmembers() if member.isfile()]
                package_json = next((m for m in members if m.name.endswith("/package.json")), None)
                if package_json is not None:
                    stream = archive.extractfile(package_json)
                    if stream:
                        return _json_coordinate(json.load(stream), "npm")
                pkg_info = next(
                    (m for m in members if m.name.endswith(("/PKG-INFO", "/METADATA"))),
                    None,
                )
                if pkg_info is not None:
                    stream = archive.extractfile(pkg_info)
                    if stream:
                        return parse_python_metadata(stream.read().decode("utf-8", "replace"))
                cargo = next((m for m in members if m.name.endswith("/Cargo.toml")), None)
                if cargo is not None:
                    stream = archive.extractfile(cargo)
                    if stream:
                        return parse_cargo_metadata(stream.read().decode("utf-8", "replace"))
        if lower.endswith((".whl", ".zip")):
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                package_json = next((n for n in names if n.endswith("/package.json")), None)
                if package_json:
                    return _json_coordinate(json.loads(archive.read(package_json)), "npm")
                metadata = next(
                    (n for n in names if n.endswith(("/METADATA", "/PKG-INFO"))),
                    None,
                )
                if metadata:
                    return parse_python_metadata(archive.read(metadata).decode("utf-8", "replace"))
    except (OSError, tarfile.TarError, zipfile.BadZipFile, json.JSONDecodeError):
        return None
    return None


def parse_rubygems_metadata(text: str) -> Coordinate | None:
    name = re.search(r"(?m)^name:\s*['\"]?([^'\"\r\n]+)", text)
    version_block = re.search(
        r"(?ms)^version:\s*!ruby/object:Gem::Version\s*\n\s+version:\s*['\"]?([^'\"\r\n]+)",
        text,
    )
    if name and version_block:
        return Coordinate("rubygems", name.group(1).strip(), version_block.group(1).strip())
    return None


def parse_python_metadata(text: str) -> Coordinate | None:
    name = re.search(r"(?mi)^Name:\s*(.+?)\s*$", text)
    version = re.search(r"(?mi)^Version:\s*(.+?)\s*$", text)
    if name and version:
        return Coordinate("pypi", name.group(1), version.group(1))
    return None


def parse_cargo_metadata(text: str) -> Coordinate | None:
    package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", text)
    if not package:
        return None
    name = re.search(r'(?m)^name\s*=\s*["\']([^"\']+)', package.group(1))
    version = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)', package.group(1))
    if name and version:
        return Coordinate("crates.io", name.group(1), version.group(1))
    return None


def iter_archives(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES):
            yield path


def index_archives(roots: Iterable[Path]) -> dict[tuple[str, str, str], list[Path]]:
    index: dict[tuple[str, str, str], list[Path]] = defaultdict(list)
    for root in roots:
        for path in iter_archives(root):
            coordinate = inspect_archive(path)
            if coordinate:
                index[coordinate_key(coordinate)].append(path.resolve())
    return index


def load_osv_references(root: Path) -> dict[tuple[str, str, str], set[str]]:
    references: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    if not root.is_dir():
        return references
    for path in root.rglob("*.json"):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        urls = {
            str(item.get("url"))
            for item in report.get("references", [])
            if isinstance(item, dict) and item.get("url")
        }
        for affected in report.get("affected", []):
            package = affected.get("package", {})
            ecosystem = normalize_ecosystem(str(package.get("ecosystem", "")))
            name = str(package.get("name", ""))
            versions = affected.get("versions", [])
            for version in versions:
                coordinate = Coordinate(ecosystem, name, str(version))
                references[coordinate_key(coordinate)].update(urls)
    return references


def request_json(url: str, contact_email: str, timeout: float) -> tuple[int, dict | list | None]:
    headers = {"Accept": "application/json", "User-Agent": "OSPtrack-artifact-audit/1.0"}
    if contact_email:
        headers["User-Agent"] += f" (mailto:{contact_email})"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return 0, None


def first_string(data: object, paths: Iterable[tuple[str, ...]]) -> str:
    for path in paths:
        value = data
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def metadata_leads(ecosystem: str, data: dict | list | None) -> tuple[str, str, str]:
    """Return repository URL, candidate artifact URL, and published integrity."""
    if not isinstance(data, dict):
        return "", "", ""
    repository = first_string(
        data,
        (
            ("repository_url",),
            ("repository", "url"),
            ("info", "project_url"),
            ("info", "home_page"),
            ("metadata", "repository"),
        ),
    )
    artifact = first_string(
        data,
        (
            ("download_url",),
            ("archive_url",),
            ("dist", "tarball"),
            ("crate", "dl_path"),
        ),
    )
    integrity = first_string(
        data,
        (
            ("integrity",),
            ("sha256",),
            ("dist", "integrity"),
            ("dist", "shasum"),
        ),
    )
    if ecosystem == "pypi":
        urls = data.get("urls")
        if isinstance(urls, list):
            source = next(
                (item for item in urls if isinstance(item, dict) and item.get("packagetype") == "sdist"),
                None,
            )
            selected = source or next((item for item in urls if isinstance(item, dict)), None)
            if selected:
                artifact = artifact or str(selected.get("url", ""))
                digests = selected.get("digests")
                if isinstance(digests, dict):
                    integrity = integrity or str(digests.get("sha256", ""))
        info = data.get("info")
        if isinstance(info, dict):
            project_urls = info.get("project_urls")
            if isinstance(project_urls, dict):
                repository = repository or next(
                    (
                        str(value)
                        for key, value in project_urls.items()
                        if isinstance(value, str)
                        and any(word in key.casefold() for word in ("source", "repository", "code"))
                    ),
                    "",
                )
    return repository, artifact, integrity


def registry_metadata_url(coordinate: Coordinate) -> str:
    quoted_name = urllib.parse.quote(coordinate.name, safe="@")
    quoted_version = urllib.parse.quote(coordinate.version, safe="")
    if coordinate.ecosystem == "npm":
        return f"https://registry.npmjs.org/{quoted_name}/{quoted_version}"
    if coordinate.ecosystem == "pypi":
        return f"https://pypi.org/pypi/{quoted_name}/{quoted_version}/json"
    if coordinate.ecosystem == "rubygems":
        return f"https://rubygems.org/api/v2/rubygems/{quoted_name}/versions/{quoted_version}.json"
    if coordinate.ecosystem == "crates.io":
        return f"https://crates.io/api/v1/crates/{quoted_name}/{quoted_version}"
    return ""


def ecosystems_url(coordinate: Coordinate) -> str:
    host = REGISTRY_HOSTS.get(coordinate.ecosystem)
    if not host:
        return ""
    name = urllib.parse.quote(coordinate.name, safe="")
    version = urllib.parse.quote(coordinate.version, safe="")
    return f"https://packages.ecosyste.ms/api/v1/registries/{host}/packages/{name}/versions/{version}"


def audit(args: argparse.Namespace) -> list[dict[str, str]]:
    coordinates = load_coordinates(args.coordinates)
    coordinates = coordinates[args.start_index - 1 :]
    if args.limit:
        coordinates = coordinates[: args.limit]
    archive_index = index_archives([args.known_archives, *args.cache_root])
    osv_references = load_osv_references(args.osv_root)
    rows: list[dict[str, str]] = []
    for position, coordinate in enumerate(coordinates, 1):
        key = coordinate_key(coordinate)
        archives = archive_index.get(key, [])
        references = sorted(osv_references.get(key, set()))
        registry_status = "not_checked"
        ecosystems_status = "not_checked"
        repository_url = ""
        candidate_artifact_url = ""
        published_integrity = ""
        registry_url = registry_metadata_url(coordinate)
        eco_url = ecosystems_url(coordinate)
        if args.online and coordinate.version and not archives:
            if registry_url:
                status, metadata = request_json(registry_url, args.contact_email, args.http_timeout)
                registry_status = str(status or "network_error")
                if status == 200:
                    repository_url, candidate_artifact_url, published_integrity = metadata_leads(
                        coordinate.ecosystem, metadata
                    )
            if eco_url:
                status, metadata = request_json(eco_url, args.contact_email, args.http_timeout)
                ecosystems_status = str(status or "network_error")
                if status == 200:
                    eco_repository, eco_artifact, eco_integrity = metadata_leads(
                        coordinate.ecosystem, metadata
                    )
                    repository_url = repository_url or eco_repository
                    candidate_artifact_url = candidate_artifact_url or eco_artifact
                    published_integrity = published_integrity or eco_integrity
        if archives:
            status = "exact_local_archive"
        elif registry_status == "200":
            status = "registry_metadata_available"
        elif ecosystems_status == "200":
            status = "ecosystems_metadata_available"
        elif references:
            status = "osv_references_only"
        else:
            status = "unresolved"
        archive = archives[0] if archives else None
        rows.append(
            {
                "input_index": str(position),
                "ecosystem": coordinate.ecosystem,
                "name": coordinate.name,
                "version": coordinate.version,
                "recovery_status": status,
                "archive_path": str(archive) if archive else "",
                "sha256": sha256_file(archive) if archive else "",
                "archive_matches": str(len(archives)),
                "osv_reference_count": str(len(references)),
                "osv_references": " ".join(references),
                "registry_metadata_status": registry_status,
                "registry_metadata_url": registry_url,
                "ecosystems_status": ecosystems_status,
                "ecosystems_url": eco_url,
                "repository_url": repository_url,
                "candidate_artifact_url": candidate_artifact_url,
                "published_integrity": published_integrity,
            }
        )
    return rows


def write_outputs(rows: list[dict[str, str]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "recovery_audit.csv"
    fields = list(rows[0]) if rows else ["ecosystem", "name", "version", "recovery_status"]
    with csv_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    statuses = Counter(row["recovery_status"] for row in rows)
    summary = {"coordinates": len(rows), "by_recovery_status": dict(sorted(statuses.items()))}
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Wrote {csv_path}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coordinates", type=Path, default=PROJECT_ROOT / "data/pkg_mal.csv")
    parser.add_argument(
        "--known-archives",
        type=Path,
        default=PROJECT_ROOT / "data/Backstabbers-Knife-Collection/samples",
    )
    parser.add_argument(
        "--osv-root",
        type=Path,
        default=PROJECT_ROOT / "data/malicious-packages-info",
    )
    parser.add_argument("--cache-root", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--contact-email", default="")
    parser.add_argument("--http-timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    if args.start_index < 1:
        parser.error("--start-index must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        rows = audit(args)
        write_outputs(rows, args.output_dir)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
