#!/usr/bin/env python3
"""Recover exact package archives from free public metadata and registry URLs.

Archives are downloaded but never extracted or executed. Only official package
registry/CDN hosts are allowed, and embedded coordinates must match the request.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from audit import (
    Coordinate,
    coordinate_key,
    ecosystems_url,
    inspect_archive,
    metadata_leads,
    registry_metadata_url,
    request_json,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = Path(__file__).resolve().parent / "outputs/recovery_audit.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/recovered-malicious-packages"
ALLOWED_ARTIFACT_HOSTS = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "files.pythonhosted.org",
    "pypi.org",
    "rubygems.org",
    "static.crates.io",
    "crates.io",
}
SUPPORTED = {"npm", "pypi", "rubygems", "crates.io"}


def safe_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@+-]+", "__", value).strip(".") or "unknown"


def artifact_extension(ecosystem: str, url: str = "") -> str:
    path = urllib.parse.urlparse(url).path.casefold()
    for extension in (".tar.gz", ".whl", ".zip", ".tgz", ".gem", ".crate"):
        if path.endswith(extension):
            return extension
    return {"npm": ".tgz", "pypi": ".tar.gz", "rubygems": ".gem", "crates.io": ".crate"}[ecosystem]


def normalize_artifact_url(ecosystem: str, url: str) -> str:
    if ecosystem == "crates.io" and url.startswith("/"):
        return "https://crates.io" + url
    return url


def allowed_artifact_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and (parsed.hostname or "").casefold() in ALLOWED_ARTIFACT_HOSTS


def download_to_temp(url: str, maximum_bytes: int, timeout: float) -> tuple[Path | None, str]:
    if not allowed_artifact_url(url):
        return None, "artifact_host_not_allowed"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "OSPtrack-artifact-recovery/1.0", "Accept": "application/octet-stream"},
    )
    temp = tempfile.NamedTemporaryFile(prefix="osptrack-recovery-", delete=False, dir="/tmp")
    temp_path = Path(temp.name)
    size = 0
    try:
        with temp, urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if not allowed_artifact_url(final_url):
                return None, "artifact_redirect_host_not_allowed"
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > maximum_bytes:
                return None, "artifact_too_large"
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > maximum_bytes:
                    return None, "artifact_too_large"
                temp.write(block)
        return temp_path, "downloaded"
    except urllib.error.HTTPError as error:
        return None, f"artifact_http_{error.code}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, "artifact_network_error"
    finally:
        if temp_path.exists() and (size > maximum_bytes or temp_path.stat().st_size == 0):
            temp_path.unlink()


def digest_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def integrity_matches(path: Path, published: str) -> tuple[bool | None, str]:
    if not published:
        return None, ""
    value = published.strip()
    if "-" in value:
        algorithm, encoded = value.split("-", 1)
        if algorithm in hashlib.algorithms_available:
            expected_hex_length = hashlib.new(algorithm).digest_size * 2
            if re.fullmatch(rf"[0-9a-fA-F]{{{expected_hex_length}}}", encoded):
                return digest_file(path, algorithm).casefold() == encoded.casefold(), algorithm
            digest = hashlib.new(algorithm, path.read_bytes()).digest()
            try:
                return digest == base64.b64decode(encoded, validate=True), algorithm
            except ValueError:
                return None, "unknown"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return digest_file(path, "sha1").casefold() == value.casefold(), "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return digest_file(path, "sha256").casefold() == value.casefold(), "sha256"
    return None, "unknown"


def candidate_rows(path: Path, limit: int | None, start_index: int) -> list[Coordinate]:
    coordinates: list[Coordinate] = []
    seen: set[tuple[str, str, str]] = set()
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            coordinate = Coordinate(row["ecosystem"], row["name"], row["version"])
            key = coordinate_key(coordinate)
            if (
                coordinate.ecosystem not in SUPPORTED
                or not coordinate.version
                or row["recovery_status"] == "exact_local_archive"
                or key in seen
            ):
                continue
            seen.add(key)
            coordinates.append(coordinate)
    coordinates = coordinates[start_index - 1 :]
    return coordinates[:limit] if limit else coordinates


def recover_one(coordinate: Coordinate, args: argparse.Namespace) -> dict[str, str]:
    result = {
        "ecosystem": coordinate.ecosystem,
        "name": coordinate.name,
        "version": coordinate.version,
        "status": "metadata_not_found",
        "metadata_source": "",
        "repository_url": "",
        "artifact_url": "",
        "published_integrity": "",
        "integrity_check": "not_available",
        "sha256": "",
        "size_bytes": "",
        "archive_path": "",
    }
    metadata = None
    registry_url = registry_metadata_url(coordinate)
    if registry_url:
        code, metadata = request_json(registry_url, args.contact_email, args.http_timeout)
        if code == 200:
            result["metadata_source"] = "registry"
    if metadata is None:
        eco_url = ecosystems_url(coordinate)
        if eco_url:
            code, metadata = request_json(eco_url, args.contact_email, args.http_timeout)
            if code == 200:
                result["metadata_source"] = "ecosystems"
    repository, artifact, integrity = metadata_leads(coordinate.ecosystem, metadata)
    artifact = normalize_artifact_url(coordinate.ecosystem, artifact)
    result.update(
        repository_url=repository,
        artifact_url=artifact,
        published_integrity=integrity,
    )
    if not artifact:
        result["status"] = "metadata_without_artifact_url" if metadata else "metadata_not_found"
        return result
    temp_path, status = download_to_temp(artifact, args.max_bytes, args.http_timeout)
    if temp_path is None:
        result["status"] = status
        return result
    try:
        extension = artifact_extension(coordinate.ecosystem, artifact)
        inspection_path = temp_path.with_name(temp_path.name + extension)
        temp_path.rename(inspection_path)
        temp_path = inspection_path
        embedded = inspect_archive(temp_path)
        if embedded is None or coordinate_key(embedded) != coordinate_key(coordinate):
            result["status"] = "embedded_coordinate_mismatch"
            return result
        integrity_ok, algorithm = integrity_matches(temp_path, integrity)
        result["integrity_check"] = (
            f"matched_{algorithm}" if integrity_ok is True else
            f"mismatch_{algorithm}" if integrity_ok is False else
            "not_available"
        )
        if integrity_ok is False:
            result["status"] = "published_integrity_mismatch"
            return result
        destination_dir = (
            args.output_root
            / safe_component(coordinate.ecosystem)
            / safe_component(coordinate.name)
            / safe_component(coordinate.version)
        )
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / (
            f"{safe_component(coordinate.name)}-{safe_component(coordinate.version)}{extension}"
        )
        if destination.exists():
            if digest_file(destination, "sha256") != digest_file(temp_path, "sha256"):
                result["status"] = "existing_archive_hash_conflict"
                return result
            temp_path.unlink()
        else:
            os.replace(temp_path, destination)
        result.update(
            status="recovered_exact_archive",
            sha256=digest_file(destination, "sha256"),
            size_bytes=str(destination.stat().st_size),
            archive_path=str(destination.resolve()),
        )
        return result
    finally:
        if temp_path.exists():
            temp_path.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-csv", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--http-timeout", type=float, default=20.0)
    parser.add_argument("--max-mib", type=int, default=50)
    parser.add_argument("--contact-email", default="")
    args = parser.parse_args()
    if args.start_index < 1 or (args.limit is not None and args.limit < 1):
        parser.error("start index and limit must be positive")
    if not 1 <= args.workers <= 16:
        parser.error("workers must be between 1 and 16")
    args.max_bytes = args.max_mib * 1024 * 1024
    return args


def main() -> int:
    args = parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    coordinates = candidate_rows(args.audit_csv, args.limit, args.start_index)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(pool.map(lambda coordinate: recover_one(coordinate, args), coordinates))
    manifest = args.output_root / "recovery_manifest.csv"
    fields = list(rows[0]) if rows else ["ecosystem", "name", "version", "status"]
    with manifest.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "attempted": len(rows),
        "by_status": dict(sorted(Counter(row["status"] for row in rows).items())),
    }
    (args.output_root / "recovery_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"Wrote {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
