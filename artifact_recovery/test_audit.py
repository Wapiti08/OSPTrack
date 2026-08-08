import io
import gzip
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from collect import artifact_extension, integrity_matches
from audit import (
    Coordinate,
    coordinate_key,
    index_archives,
    load_osv_references,
    metadata_leads,
)


class RecoveryAuditTest(unittest.TestCase):
    def test_preserves_pypi_wheel_extension(self):
        self.assertEqual(
            artifact_extension("pypi", "https://files.pythonhosted.org/demo-1.0-py3-none-any.whl"),
            ".whl",
        )

    def test_accepts_ecosystems_hex_integrity_notation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"content")
            expected = hashlib.sha256(b"content").hexdigest()
            self.assertEqual(integrity_matches(path, f"sha256-{expected}"), (True, "sha256"))

    def test_indexes_npm_archive_by_embedded_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "arbitrary-name.tgz"
            payload = json.dumps({"name": "@scope/demo", "version": "1.2.3"}).encode()
            info = tarfile.TarInfo("package/package.json")
            info.size = len(payload)
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.addfile(info, io.BytesIO(payload))

            index = index_archives([root])

            key = coordinate_key(Coordinate("npm", "@scope/demo", "1.2.3"))
            self.assertEqual(index[key], [archive_path.resolve()])

    def test_maps_osv_versions_and_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "Demo_Name"},
                        "versions": ["1.0"],
                    }
                ],
                "references": [{"type": "EVIDENCE", "url": "https://example.test/report"}],
            }
            (root / "report.json").write_text(json.dumps(report), encoding="utf-8")

            references = load_osv_references(root)

            key = coordinate_key(Coordinate("pypi", "demo-name", "1.0"))
            self.assertEqual(references[key], {"https://example.test/report"})

    def test_indexes_rubygems_archive_by_embedded_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "arbitrary-name.gem"
            metadata = gzip.compress(
                b"--- !ruby/object:Gem::Specification\n"
                b"name: demo-gem\n"
                b"version: !ruby/object:Gem::Version\n"
                b"  version: 2.0.1\n"
            )
            info = tarfile.TarInfo("metadata.gz")
            info.size = len(metadata)
            with tarfile.open(archive_path, "w") as archive:
                archive.addfile(info, io.BytesIO(metadata))

            index = index_archives([root])

            key = coordinate_key(Coordinate("rubygems", "demo-gem", "2.0.1"))
            self.assertEqual(index[key], [archive_path.resolve()])

    def test_extracts_pypi_recovery_leads_without_downloading(self):
        metadata = {
            "info": {"project_urls": {"Source": "https://example.test/repository"}},
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://example.test/demo-1.0.tar.gz",
                    "digests": {"sha256": "abc123"},
                }
            ],
        }

        self.assertEqual(
            metadata_leads("pypi", metadata),
            (
                "https://example.test/repository",
                "https://example.test/demo-1.0.tar.gz",
                "abc123",
            ),
        )


if __name__ == "__main__":
    unittest.main()
