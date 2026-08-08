import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ext"))
from build_label_data import analysis_quality, coordinate, load_malicious_round, read_local_runs


class BuildLabelDataTest(unittest.TestCase):
    def test_coordinate_normalizes_pypi_name_without_coercing_version(self):
        self.assertEqual(coordinate("PyPI", "Some_Pkg.Name", "01.0"), ("pypi", "some-pkg-name", "01.0"))

    def test_analysis_quality_preserves_partial_trace(self):
        status, trace, populated = analysis_quality({
            "install": {"Status": "error_analysis", "Commands": ["curl"]},
            "import": {"Status": "completed", "DNS": ["example.test"]},
        })
        self.assertEqual(status, "partial_completed")
        self.assertTrue(trace)
        self.assertEqual(populated, 2)

    def test_only_manifested_local_coordinates_are_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "results").mkdir()
            with (root / "analysis_runs.csv").open("w", newline="", encoding="utf-8") as target:
                writer = csv.DictWriter(target, fieldnames=[
                    "timestamp_utc", "ecosystem", "name", "version", "source",
                    "local_archive", "returncode", "timed_out",
                ])
                writer.writeheader()
                writer.writerow({"timestamp_utc": "2", "ecosystem": "pypi", "name": "local_pkg",
                                 "version": "1.0", "source": "backstabbers",
                                 "local_archive": "/samples/local.whl", "returncode": "0", "timed_out": "False"})
                writer.writerow({"timestamp_utc": "1", "ecosystem": "pypi", "name": "remote",
                                 "version": "1.0", "source": "registry", "local_archive": "",
                                 "returncode": "0", "timed_out": "False"})
            for name in ("local_pkg", "remote"):
                report = {"Package": {"Ecosystem": "pypi", "Name": name, "Version": "1.0"},
                          "Analysis": {"install": {"Status": "completed", "Files": [name]}}}
                (root / "results" / f"pypi-{name}-1.0.json").write_text(json.dumps(report))
            self.assertEqual(len(read_local_runs(root)), 1)
            records = load_malicious_round(root, "test_local")
            self.assertEqual(set(records), {("pypi", "local-pkg", "1.0")})
            row = next(iter(records.values()))[0]
            self.assertEqual(row["Simulation_Source"], "test_local")
            self.assertEqual(row["Local_Archive"], "/samples/local.whl")


if __name__ == "__main__":
    unittest.main()
