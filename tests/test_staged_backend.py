import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fidb_poc.backend_benchmark import (
    _python_executable,
    backend_benchmark_preview,
    compare_backend_results,
)
from fidb_poc.cli import main
from fidb_poc.pipeline import BuildRecord
from fidb_poc.staged_backend import (
    execute_build_stage,
    load_staged_job,
    write_staged_job,
)
from fidb_poc.width_benchmark import _selected_groups
from fidb_poc import staged_worker


class StagedBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        _compilation, groups = _selected_groups(
            cls.root,
            ("linux-x86-64-gcc-13",),
            ("baseline_o2",),
        )
        cls.configuration = groups[0]

    def test_job_round_trip_preserves_resolved_authority(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            group_root = Path(directory)
            (group_root / "jobs").mkdir()
            job_path = group_root / "jobs/job.json"

            write_staged_job(self.configuration, group_root, job_path, index=7)
            expected = json.loads(job_path.read_text())
            observed, configuration, observed_root = load_staged_job(job_path)

        self.assertEqual(observed, expected)
        self.assertEqual(configuration, self.configuration)
        self.assertEqual(observed_root, group_root.resolve())

    def test_job_digest_rejects_authority_mutation(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            group_root = Path(directory)
            (group_root / "jobs").mkdir()
            job_path = group_root / "jobs/job.json"
            write_staged_job(self.configuration, group_root, job_path, index=1)
            document = json.loads(job_path.read_text())
            document["configuration"]["routes"][0]["compiler_family"] = "mutated"
            job_path.write_text(json.dumps(document))

            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                load_staged_job(job_path)

    def test_build_stage_does_not_start_or_import_a_jvm(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            group_root = Path(directory)
            downloads = group_root / "work/downloads"
            downloads.mkdir(parents=True)
            archive = downloads / "source.tar.gz"
            archive.write_bytes(b"source")
            source = group_root / "source"
            source.mkdir()

            def fake_build(*_args, **_kwargs):
                object_path = group_root / "work/builds/example.o"
                object_path.parent.mkdir(parents=True, exist_ok=True)
                object_path.write_bytes(b"object")
                return BuildRecord(status="built"), [object_path]

            with (
                mock.patch(
                    "fidb_poc.staged_backend.download_library", return_value=archive
                ),
                mock.patch(
                    "fidb_poc.staged_backend.extract_source", return_value=source
                ),
                mock.patch(
                    "fidb_poc.staged_backend.detect_project",
                    return_value=object(),
                ),
                mock.patch(
                    "fidb_poc.staged_backend.build_library", side_effect=fake_build
                ),
            ):
                result = execute_build_stage(self.configuration, group_root)

            self.assertEqual(result["pipeline_error"], "")
            self.assertTrue(Path(result["state_path"]).is_file())
            self.assertNotIn("ghidra_fid", execute_build_stage.__globals__)

    def test_preview_is_disarmed_and_records_two_pool_widths(self):
        preview = backend_benchmark_preview(
            self.root,
            backend="python-staged-v1",
            route_ids=("linux-x86-64-gcc-13",),
            treatment_ids=("baseline_o2",),
            build_workers=8,
            analysis_workers=4,
            build_jobs_per_cell=2,
            heap_mib=3072,
            core_limit=2,
        )

        self.assertEqual(preview["state"], "disarmed-preview")
        self.assertEqual(preview["build_workers"], 8)
        self.assertEqual(preview["analysis_workers"], 4)
        self.assertEqual(preview["java_tool_options"], "-Xmx3072m -Dcpu.core.limit=2")

    def test_cli_preview_does_not_execute(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "benchmark-backend",
                    "--project-root",
                    str(self.root),
                    "--backend",
                    "rust-staged-v1",
                    "--route",
                    "linux-x86-64-gcc-13",
                    "--treatment",
                    "baseline_o2",
                    "--build-workers",
                    "4",
                    "--analysis-workers",
                    "2",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["state"], "disarmed-preview")

    def test_python_launcher_preserves_virtualenv_symlink(self):
        with mock.patch(
            "fidb_poc.backend_benchmark.sys.executable", ".venv/bin/python"
        ):
            launcher = _python_executable()

        self.assertEqual(launcher, self.root / ".venv/bin/python")

    def test_analysis_service_frames_result_after_noisy_stdout(self):
        def fake_analysis(*_args, **_kwargs):
            print("native Ghidra diagnostic")
            return {"index": 4, "pipeline_error": ""}

        output = io.StringIO()
        diagnostic = io.StringIO()
        request = io.StringIO('{"job_path":"/tmp/job.json"}\n')
        with (
            mock.patch.object(staged_worker, "execute_analysis_job", fake_analysis),
            mock.patch.object(staged_worker.sys, "stdin", request),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(diagnostic),
        ):
            status = staged_worker._service([])

        self.assertEqual(status, 0)
        line = output.getvalue().strip()
        self.assertTrue(line.startswith(staged_worker.SERVICE_FRAME))
        self.assertEqual(
            json.loads(line.removeprefix(staged_worker.SERVICE_FRAME))["index"], 4
        )
        self.assertIn("native Ghidra diagnostic", diagnostic.getvalue())

    def test_comparison_uses_canonical_records_not_container_order(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            temporary = Path(directory)
            authorities = {
                "width_id": "example",
                "fixed_recipe": "recipes/example.toml",
                "compilation_digest": "a" * 64,
                "routes": ["route-a"],
                "treatments": ["baseline_o2"],
            }
            paths = []
            for name, records, artifact in (
                ("reference", ['{"hash":1}', '{"hash":2}'], "b" * 64),
                ("candidate", ['{ "hash": 2 }', '{"hash":1}'], "c" * 64),
            ):
                root = temporary / name
                libraries = root / "group-001/artifacts/libs"
                signatures = libraries / "fid-signatures/example.jsonl"
                signatures.parent.mkdir(parents=True)
                signatures.write_text("\n".join(records) + "\n", encoding="utf-8")
                (libraries / "fidb_manifest.csv").write_text(
                    "route,treatment,status,analysis_artifact_sha256,fidb_sha256,"
                    "fid_signatures_sha256,fid_signatures_path,fid_attempted,"
                    "fid_added,fid_excluded\n"
                    f"route-a,baseline_o2,complete,{artifact},{name},{name},"
                    "artifacts/libs/fid-signatures/example.jsonl,2,2,0\n",
                    encoding="utf-8",
                )
                result = root / "benchmark-result.json"
                result.write_text(json.dumps(authorities), encoding="utf-8")
                paths.append(result)

            comparison = compare_backend_results(*paths)

        self.assertTrue(comparison["authority_match"])
        self.assertTrue(comparison["semantic_match"])
        self.assertFalse(comparison["artifact_reproducibility_match"])
        self.assertEqual(len(comparison["container_or_order_differences"]), 2)
        self.assertEqual(
            comparison["reference_canonical_digest"],
            comparison["candidate_canonical_digest"],
        )


if __name__ == "__main__":
    unittest.main()
