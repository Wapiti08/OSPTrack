import csv
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from data_create.simu_run import (
    PackageRef,
    build_analysis_command,
    build_local_package_index,
    find_local_archive,
    is_analyzed,
    pack_info_load,
    result_prefix,
)


class LocalPackageIndexTest(unittest.TestCase):
    def test_matches_normalized_pypi_name_and_exact_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            samples = Path(temp_dir)
            version_dir = samples / "pypi" / "Foo_Bar" / "1.0"
            version_dir.mkdir(parents=True)
            archive = version_dir / "Foo_Bar-1.0.tar.gz"
            archive.touch()

            index = build_local_package_index(samples)

            self.assertEqual(
                find_local_archive(PackageRef("PyPI", "foo-bar", "1.0"), index),
                archive.resolve(),
            )
            self.assertIsNone(find_local_archive(PackageRef("pypi", "foo-bar", "1.1"), index))

    def test_uses_npm_metadata_for_scoped_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            samples = Path(temp_dir)
            version_dir = samples / "npm" / "scope__package" / "2.0.0"
            version_dir.mkdir(parents=True)
            archive = version_dir / "package-2.0.0.tgz"
            archive.touch()
            (version_dir / "metadata.json").write_text(
                json.dumps({"name": "@scope/package", "version": "2.0.0"}),
                encoding="utf-8",
            )

            index = build_local_package_index(samples)

            self.assertEqual(
                find_local_archive(PackageRef("npm", "@scope/package", "2.0.0"), index),
                archive.resolve(),
            )

    def test_prefers_pypi_source_distribution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            samples = Path(temp_dir)
            version_dir = samples / "pypi" / "example" / "3.0"
            version_dir.mkdir(parents=True)
            wheel = version_dir / "example-3.0-py3-none-any.whl"
            source = version_dir / "example-3.0.tar.gz"
            wheel.touch()
            source.touch()

            index = build_local_package_index(samples)

            self.assertEqual(
                find_local_archive(PackageRef("pypi", "example", "3.0"), index),
                source.resolve(),
            )


class InputAndResultTest(unittest.TestCase):
    def test_csv_loader_preserves_version_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "packages.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as destination:
                writer = csv.DictWriter(destination, fieldnames=("ecosystem", "name", "version"))
                writer.writeheader()
                writer.writerow({"ecosystem": "PyPI", "name": "demo", "version": "1.0"})

            self.assertEqual(pack_info_load(csv_path), [PackageRef("pypi", "demo", "1.0")])

    def test_completed_result_must_embed_matching_package(self):
        package = PackageRef("pypi", "demo", "1.0")
        with tempfile.TemporaryDirectory() as temp_dir:
            results = Path(temp_dir)
            result_path = results / f"{result_prefix(package)}.json"
            result_path.write_text(
                json.dumps(
                    {
                        "Package": {"Ecosystem": "pypi", "Name": "other", "Version": "1.0"},
                        "Analysis": {"install": {"Status": "completed"}},
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(is_analyzed(package, results))

            result_path.write_text(
                json.dumps(
                    {
                        "Package": {"Ecosystem": "pypi", "Name": "demo", "Version": "1.0"},
                        "Analysis": {"install": {"Status": "error_analysis"}},
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(is_analyzed(package, results))

            result_path.write_text(
                json.dumps(
                    {
                        "Package": {"Ecosystem": "pypi", "Name": "demo", "Version": "1.0"},
                        "Analysis": {"install": {"Status": "completed"}},
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(is_analyzed(package, results))

    def test_local_command_keeps_version_and_uses_argument_list(self):
        package = PackageRef("pypi", "name with spaces", "1.0")
        command = build_analysis_command(
            "/tmp/run_analysis.sh",
            package,
            local_archive=Path("/tmp/archive with spaces.tar.gz"),
            offline=True,
        )

        self.assertIn("-local", command)
        self.assertIn(str(Path("/tmp/archive with spaces.tar.gz").resolve()), command)
        self.assertEqual(command[command.index("-version") + 1], "1.0")
        self.assertIn("-offline", command)


class ResultArchivingTest(unittest.TestCase):
    def test_shell_wrapper_only_archives_current_run_and_keeps_sidecars_paired(self):
        project_root = Path(__file__).resolve().parents[1]
        wrapper = project_root / "run_analysis.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "sample-1.0.tar.gz"
            archive.touch()
            fake_docker = root / "fake-docker.sh"
            fake_docker.write_text(
                """#!/bin/bash
for ((index=1; index <= $#; index++)); do
    if [[ "${!index}" == "-v" ]]; then
        index=$((index+1))
        mount_spec="${!index}"
        host_path="${mount_spec%%:*}"
        container_spec="${mount_spec#*:}"
        container_path="${container_spec%%:*}"
        if [[ "$container_path" == "/results" ]]; then
            printf '{"run":"%s"}' "${FAKE_RUN_ID}" > "$host_path/results.json"
            printf 'attrs-%s' "${FAKE_RUN_ID}" > "$host_path/results.json.attrs"
        fi
    fi
done
""",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            output_dirs = {
                "RESULTS_DIR": root / "results",
                "STATIC_RESULTS_DIR": root / "static",
                "FILE_WRITE_RESULTS_DIR": root / "writes",
                "ANALYZED_PACKAGES_DIR": root / "packages",
                "LOGS_DIR": root / "logs",
                "STRACE_LOGS_DIR": root / "strace",
            }
            environment = os.environ.copy()
            environment.update({key: str(value) for key, value in output_dirs.items()})
            environment["CONTAINER_DIR_OVERRIDE"] = str(root / "containers")
            environment["DOCKER_BIN"] = str(fake_docker)
            command = [
                str(wrapper),
                "-nointeractive",
                "-ecosystem",
                "pypi",
                "-package",
                "demo",
                "-version",
                "1.0",
                "-local",
                str(archive),
            ]

            environment["FAKE_RUN_ID"] = "first"
            subprocess.run(command, env=environment, check=True, capture_output=True, text=True)
            environment["FAKE_RUN_ID"] = "second"
            subprocess.run(command, env=environment, check=True, capture_output=True, text=True)

            results = output_dirs["RESULTS_DIR"]
            self.assertEqual((results / "pypi-demo-1.0.json").read_text(), '{"run":"first"}')
            self.assertEqual((results / "pypi-demo-1.0.attrs").read_text(), "attrs-first")
            self.assertEqual((results / "pypi-demo-1.0.2.json").read_text(), '{"run":"second"}')
            self.assertEqual((results / "pypi-demo-1.0.2.attrs").read_text(), "attrs-second")


if __name__ == "__main__":
    unittest.main()
