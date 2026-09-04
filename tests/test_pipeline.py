import csv
import hashlib
import io
import tarfile
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fidb_poc.pipeline import (
    BuildRecord,
    PipelineError,
    _build_workspace_name,
    _stage_build_inputs,
    _populate_group,
    _missing_file_markers,
    _validate_population_report,
    compiler_identity,
    download_library,
    find_pyghidra,
    ghidra_environment,
    _safe_member_path,
    _validate_objects,
    execute,
    extract_source,
    java_identity,
    pipeline_environment,
    plan,
    populate_fidbs,
    resolve_executable,
    run_command,
    sha256,
    write_manifest,
)
from fidb_poc.adapters import Detection
from fidb_poc.config import BuildInput, Library, load_configuration, select_configuration


class PipelineTests(unittest.TestCase):
    def test_recipe_build_inputs_stage_only_at_fixed_adapter_locations(self):
        source_input = BuildInput(
            kind="source-tree",
            name="zlib",
            version="1.3.1",
            url="https://example.invalid/zlib.tar.gz",
            sha256="a" * 64,
            filename="zlib-1.3.1.tar.gz",
            source_directory="zlib-1.3.1",
        )
        package_input = BuildInput(
            kind="meson-package-cache",
            name="libffi-wrap-patch",
            version="3.5.2-1",
            url="https://example.invalid/libffi-patch.zip",
            sha256="b" * 64,
            filename="libffi_3.5.2-1_patch.zip",
        )
        library = Library(
            name="example",
            version="1.0",
            url="https://example.invalid/example.tar.gz",
            sha256="c" * 64,
            source_directory="example-1.0",
            project_markers=("meson.build",),
            allowed_build_systems=("meson",),
            preferred_build_system="meson",
            static_archives=("libexample.a",),
            build_inputs=(source_input, package_input),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "prepared-zlib"
            source.mkdir()
            (source / "zlib.h").write_text("/* pinned */\n", encoding="utf-8")
            package = root / "cached-patch"
            package.write_bytes(b"pinned patch")
            cell = root / "cell"
            cell.mkdir()

            _stage_build_inputs(
                library,
                {
                    source_input.cache_key: source,
                    package_input.cache_key: package,
                },
                cell,
            )

            self.assertEqual(
                (cell / "fidb-inputs/zlib-1.3.1/zlib.h").read_text(),
                "/* pinned */\n",
            )
            self.assertEqual(
                (
                    cell / "subprojects/packagecache/libffi_3.5.2-1_patch.zip"
                ).read_bytes(),
                b"pinned patch",
            )

    def test_missing_prepared_recipe_input_fails_closed(self):
        build_input = BuildInput(
            kind="source-tree",
            name="zlib",
            version="1.3.1",
            url="https://example.invalid/zlib.tar.gz",
            sha256="a" * 64,
            filename="zlib-1.3.1.tar.gz",
            source_directory="zlib-1.3.1",
        )
        example = Library(
            name="example",
            version="1.0",
            url="https://example.invalid/example.tar.gz",
            sha256="b" * 64,
            source_directory="example-1.0",
            project_markers=("CMakeLists.txt",),
            allowed_build_systems=("cmake",),
            preferred_build_system="cmake",
            static_archives=("libexample.a",),
            build_inputs=(build_input,),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                PipelineError, "prepared build input is missing"
            ):
                _stage_build_inputs(example, {}, Path(temporary))

    def test_windows_build_workspace_is_short_and_identity_stable(self):
        configuration = load_configuration(
            Path(__file__).resolve().parents[1] / "worker.toml",
            request_override=("zlib",),
        )
        base_route = next(
            item
            for item in configuration.routes
            if item.id == "linux-x86_64-gnu-gcc"
        )
        windows_route = SimpleNamespace(
            **{
                **base_route.__dict__,
                "id": "windows-x86-64-llvm-mingw-clang-20",
                "target_os": "windows",
            }
        )
        treatment = configuration.treatments[0]
        library = configuration.libraries[0]

        first = _build_workspace_name(library, windows_route, treatment)
        second = _build_workspace_name(library, windows_route, treatment)

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("zlib-"))
        self.assertLessEqual(len(first), 21)

    def test_native_library_can_reuse_content_addressed_source_cache(self):
        payload = b"cached source archive"
        digest = hashlib.sha256(payload).hexdigest()
        library = Library(
            name="example",
            version="1.0",
            url="https://example.invalid/example.tar.gz",
            sha256=digest,
            source_directory="example-1.0",
            project_markers=("configure",),
            allowed_build_systems=("autoconf",),
            preferred_build_system="autoconf",
            static_archives=("libexample.a",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            downloads = Path(temporary) / "downloads"
            downloads.mkdir()
            cached = downloads / digest
            cached.write_bytes(payload)

            with patch("fidb_poc.pipeline.acquire_pinned") as acquire:
                selected = download_library(
                    library, downloads, content_addressed=True
                )

        self.assertEqual(selected, cached)
        acquire.assert_not_called()

    def test_file_marker_validation_accepts_reviewed_i386_alias(self):
        description = "ELF 32-bit LSB relocatable, Intel i386, version 1 (SYSV)"

        self.assertEqual(
            _missing_file_markers(
                description, ("ELF 32-bit LSB", "relocatable", "Intel 80386")
            ),
            [],
        )
        self.assertEqual(
            _missing_file_markers(description, ("ELF 64-bit LSB",)),
            ["ELF 64-bit LSB"],
        )

    def test_coff_object_validation_uses_header_not_file_heuristics(self):
        route = SimpleNamespace(
            id="windows-x86-64-test",
            binary_format="PE/COFF",
            architecture="x86_64",
            object_file_markers=("x86-64 COFF object file",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            object_path = Path(temporary) / "ambiguous.o"
            header = bytearray(20)
            header[0:2] = (0x8664).to_bytes(2, "little")
            header[2:4] = (10).to_bytes(2, "little")
            object_path.write_bytes(header + b"RenderWare-like payload")
            with patch("fidb_poc.pipeline.subprocess.run") as file_command:
                _validate_objects([object_path], route, {})

        file_command.assert_not_called()

    def test_xcrun_route_hashes_the_resolved_sdk_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            xcrun = root / "xcrun"
            clang = root / "clang"
            xcrun.touch()
            clang.touch()
            completed = SimpleNamespace(stdout=f"{clang}\n", stderr="", returncode=0)
            with (
                patch("fidb_poc.pipeline.shutil.which", return_value=str(xcrun)),
                patch(
                    "fidb_poc.pipeline.subprocess.run", return_value=completed
                ) as run,
            ):
                resolved = resolve_executable(
                    (str(xcrun), "--sdk", "macosx", "clang"), {}
                )

        self.assertEqual(resolved, clang)
        self.assertEqual(
            run.call_args.args[0],
            [str(xcrun), "--sdk", "macosx", "--find", "clang"],
        )

    def test_run_command_verbose_streams_and_still_matches_buffered_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "logs" / "cmd.log"
            command = ["python3", "-c", "print('line1'); print('line2')"]
            printed = []
            with patch(
                "builtins.print", side_effect=lambda *a: printed.append(" ".join(a))
            ):
                result = run_command(
                    command,
                    cwd=None,
                    environment={"PATH": "/usr/bin:/bin"},
                    log_path=log_path,
                    verbose=True,
                )
            self.assertEqual(result.returncode, 0)
            self.assertIn("line1\nline2\n", result.stdout)
            self.assertTrue(any("line1" in line for line in printed))
            logged = log_path.read_text(encoding="utf-8")
            self.assertIn("line1", logged)
            self.assertIn("started_at_utc=", logged)
            self.assertIn("finished_at_utc=", logged)
            self.assertIn("duration_ns=", logged)
            self.assertIn("outcome=completed", logged)
            self.assertIn("returncode=0", logged)

    def test_ghidra_environment_isolates_linux_xdg_directories(self):
        inherited = {
            "XDG_CONFIG_HOME": "/read-only/config",
            "XDG_CACHE_HOME": "/read-only/cache",
            "XDG_DATA_HOME": "/read-only/data",
            "XDG_STATE_HOME": "/read-only/state",
            "XDG_RUNTIME_DIR": "/read-only/runtime",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ghidra-user"
            with patch.dict("os.environ", inherited):
                environment = ghidra_environment(root)

            self.assertEqual(environment["HOME"], str(root.resolve()))
            for name, inherited_path in inherited.items():
                self.assertNotEqual(environment[name], inherited_path)
                self.assertTrue(Path(environment[name]).is_dir())
            self.assertEqual(
                Path(environment["XDG_RUNTIME_DIR"]).stat().st_mode & 0o777,
                0o700,
            )

    def test_compiler_identity_runs_in_an_isolated_directory(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("zlib",)
        )
        route = next(
            row for row in configuration.routes if row.id == "linux-x86_64-gnu-gcc"
        )
        completed = SimpleNamespace(
            stdout="gcc (GCC) 15.3.1 - Free Software Foundation",
            stderr="",
            returncode=0,
        )

        with (
            patch(
                "fidb_poc.pipeline.resolve_executable",
                return_value=Path("/usr/bin/gcc"),
            ),
            patch("fidb_poc.pipeline.subprocess.run", return_value=completed) as run,
        ):
            executable, version = compiler_identity(route, {})

        probe_directory = Path(run.call_args.kwargs["cwd"])
        self.assertEqual(executable, Path("/usr/bin/gcc"))
        self.assertEqual(version, completed.stdout)
        self.assertTrue(probe_directory.name.startswith("fidb-compiler-identity-"))
        self.assertFalse(probe_directory.exists())

    def test_pyghidra_launcher_is_resolved_beside_headless(self):
        with tempfile.TemporaryDirectory() as temporary:
            support = Path(temporary)
            headless = support / "analyzeHeadless"
            launcher = support / "pyghidraRun"
            launcher.touch()

            self.assertEqual(find_pyghidra(headless), launcher)

    def test_missing_pyghidra_launcher_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            headless = Path(temporary) / "analyzeHeadless"

            with self.assertRaisesRegex(PipelineError, "PyGhidra launcher"):
                find_pyghidra(headless)

    def test_plan_lists_selected_cells_without_running_tools(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )

        lines = plan(configuration)

        self.assertEqual(
            lines[0], "Plan: 1 libraries; 1 routes; 1 treatments; 1 cells (1 runnable)"
        )
        self.assertEqual(
            lines[1],
            "- zlib-1.3.1 | linux-x86_64-gnu-gcc | baseline_o2 | runnable",
        )

    def test_archive_path_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(PipelineError):
                _safe_member_path(root, "../escape")
            with self.assertRaises(PipelineError):
                _safe_member_path(root, "/absolute")

    def test_manifest_is_readable_csv(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "manifest.csv"
            record = BuildRecord(
                library="zlib",
                version="1.3.1",
                route="linux-x86_64-gnu-gcc",
                target_os="linux",
                architecture="x86_64",
                binary_format="ELF",
                source_url="https://example.invalid/zlib.tar.gz",
                source_sha256="a" * 64,
                compiler_command="gcc",
                compiler_path="/usr/bin/gcc",
                compiler_sha256="b" * 64,
                compiler_version=(
                    "gcc (GCC) 15.3.1 | Copyright Free Software Foundation"
                ),
                compiler_flags="-O2",
                static_archive_path="work/libz.a",
                static_archive_sha256="c" * 64,
                object_count=15,
            )
            write_manifest([record], destination)
            with destination.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)

            self.assertEqual(
                reader.fieldnames, [field.name for field in fields(record)]
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["library"], "zlib")
            self.assertEqual(rows[0]["version"], "1.3.1")
            self.assertEqual(rows[0]["route"], "linux-x86_64-gnu-gcc")
            self.assertEqual(rows[0]["object_count"], "15")
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)

    def test_population_report_must_reconcile_before_completion(self):
        root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            root / "worker.toml", request_override=("zlib",)
        )
        library = configuration.libraries[0]
        group_id = "linux-x86_64-gnu-gcc-baseline_o2"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            fidb = output / f"{library.identifier}-{group_id}.fidb"
            fidb.write_bytes(b"fidb")
            signatures = output / (
                f"{library.identifier}-{group_id}.fid-signatures.jsonl"
            )
            signatures.write_text("{}\n", encoding="utf-8")
            population = {
                "library": "zlib",
                "version": "1.3.1",
                "variant": group_id,
                "fidb_path": str(fidb),
                "fid_signatures_path": str(signatures),
                "records": 113,
                "unique_full_hashes": 100,
                "unique_signatures": 105,
                "program_count": 15,
                "attempted": 124,
                "added": 113,
                "excluded": 11,
            }

            rows = _validate_population_report(
                [population], [library], group_id, output, {"zlib": 15}
            )
            self.assertEqual(rows["zlib"], population)

            population["excluded"] = 10
            with self.assertRaisesRegex(PipelineError, "do not reconcile"):
                _validate_population_report(
                    [population], [library], group_id, output, {"zlib": 15}
                )

            population["excluded"] = 11
            with self.assertRaisesRegex(PipelineError, "program count"):
                _validate_population_report(
                    [population], [library], group_id, output, {"zlib": 14}
                )

    def test_pipeline_environment_drops_inherited_build_flags(self):
        inherited = {
            "PATH": "/usr/bin",
            "JDK_JAVA_OPTIONS": "-XX:-UseContainerSupport",
            "CFLAGS": "-DINJECTED",
            "CPPFLAGS": "-I/untrusted",
            "LDFLAGS": "-L/untrusted",
            "MAKEFLAGS": "-f/untrusted",
            "CONFIG_SITE": "/untrusted/config.site",
        }
        with patch.dict("os.environ", inherited, clear=True):
            environment = pipeline_environment()

        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["JDK_JAVA_OPTIONS"], "-XX:-UseContainerSupport")
        for name in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS", "CONFIG_SITE"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["LC_ALL"], "C")

    def test_cached_source_tampering_is_discarded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "demo.tar.gz"
            original = b"int demo(void) { return 1; }\n"
            with tarfile.open(archive, "w:gz") as source_tar:
                directory = tarfile.TarInfo("demo-1.0")
                directory.type = tarfile.DIRTYPE
                source_tar.addfile(directory)
                member = tarfile.TarInfo("demo-1.0/demo.c")
                member.size = len(original)
                member.mtime = 1_700_000_000
                source_tar.addfile(member, io.BytesIO(original))
                helper = tarfile.TarInfo("demo-1.0/configure-helper")
                helper.mode = 0o4755
                helper_bytes = b"#!/bin/sh\nexit 0\n"
                helper.size = len(helper_bytes)
                source_tar.addfile(helper, io.BytesIO(helper_bytes))
                helper_link = tarfile.TarInfo("demo-1.0/configure-link")
                helper_link.type = tarfile.SYMTYPE
                helper_link.linkname = "configure-helper"
                source_tar.addfile(helper_link)
            library = Library(
                name="demo",
                version="1.0",
                url="https://example.invalid/demo.tar.gz",
                sha256=sha256(archive),
                source_directory="demo-1.0",
                project_markers=("demo.c",),
                allowed_build_systems=("make",),
                preferred_build_system="make",
                static_archives=("libdemo.a",),
            )
            sources = root / "sources"
            first = extract_source(library, archive, sources)
            (first / "demo.c").write_text("tampered", encoding="utf-8")

            second = extract_source(library, archive, sources)

            self.assertEqual((second / "demo.c").read_bytes(), original)
            self.assertEqual(int((second / "demo.c").stat().st_mtime), 1_700_000_000)
            self.assertEqual((second / "demo.c").stat().st_mode & 0o7777, 0o644)
            self.assertEqual(
                (second / "configure-helper").stat().st_mode & 0o7777,
                0o755,
            )
            self.assertTrue((second / "configure-link").is_symlink())
            self.assertEqual(
                (second / "configure-link").read_bytes(), helper_bytes
            )

    def test_source_archive_symlink_cannot_escape_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "demo.tar.gz"
            with tarfile.open(archive, "w:gz") as source_tar:
                directory = tarfile.TarInfo("demo-1.0")
                directory.type = tarfile.DIRTYPE
                source_tar.addfile(directory)
                link = tarfile.TarInfo("demo-1.0/escape")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                source_tar.addfile(link)
            library = Library(
                name="demo",
                version="1.0",
                url="https://example.invalid/demo.tar.gz",
                sha256=sha256(archive),
                source_directory="demo-1.0",
                project_markers=("escape",),
                allowed_build_systems=("make",),
                preferred_build_system="make",
                static_archives=("libdemo.a",),
            )

            with self.assertRaisesRegex(PipelineError, "symlink target escapes"):
                extract_source(library, archive, root / "sources")

    def test_java_identity_prefers_java_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            java = Path(temporary) / "jdk/bin/java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "#!/bin/sh\necho 'openjdk version \"21.0.11\"' >&2\n",
                encoding="utf-8",
            )
            java.chmod(0o755)

            executable, version, major = java_identity(
                {"JAVA_HOME": str(java.parents[1]), "PATH": "/unavailable"}
            )

            self.assertEqual(executable, java.resolve())
            self.assertEqual(version, "21.0.11")
            self.assertEqual(major, 21)

    def test_population_schema_failure_cleans_partial_fidbs(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.toml", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        library = configuration.libraries[0]
        route = configuration.routes[0]
        treatment = configuration.treatments[0]
        key = (library.identifier, route.id, treatment.id)
        record = BuildRecord(status="built")
        group_id = f"{route.id}-{treatment.id}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = (
                root
                / "work/ghidra/candidates"
                / group_id
                / f"{library.identifier}-{group_id}.fidb"
            )
            published = root / "artifacts/libs/fidb" / candidate.name
            candidate.parent.mkdir(parents=True)
            published.parent.mkdir(parents=True)
            candidate.write_bytes(b"partial")
            published.write_bytes(b"partial")

            with patch(
                "fidb_poc.pipeline._populate_group",
                side_effect=ValueError("malformed report schema"),
            ):
                populate_fidbs(configuration, root, {key: record}, {key: []})

            self.assertEqual(record.status, "fid_failed")
            self.assertIn("malformed report schema", record.error)
            self.assertFalse(candidate.exists())
            self.assertFalse(published.exists())

    def test_populate_group_builds_fidb_via_inprocess_pyghidra(self):
        """`_populate_group` must drive `ghidra_fid.build_library_fidb` (the
        in-process pyghidra API) rather than shelling out to
        analyzeHeadless/pyghidraRun -- that subprocess round-trip is what
        hung indefinitely on a pip-less venv.
        """
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.toml", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        library = configuration.libraries[0]
        route = configuration.routes[0]
        treatment = configuration.treatments[0]
        key = (library.identifier, route.id, treatment.id)
        records = {key: BuildRecord(status="built")}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            headless = root / "ghidra/support/analyzeHeadless"
            headless.parent.mkdir(parents=True)
            headless.write_text("#!/bin/sh\n", encoding="utf-8")
            headless.chmod(0o755)
            properties = root / "ghidra/Ghidra/application.properties"
            properties.parent.mkdir(parents=True)
            properties.write_text(
                "application.version=12.0.4\n"
                "application.release.name=PUBLIC\n"
                "application.build.date=2026-01-01\n",
                encoding="utf-8",
            )
            obj = root / "adler32.o"
            obj.write_bytes(b"fake object")
            objects = {key: [obj]}

            def fake_build(*, output, **_kwargs):
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"fake fidb")
                return {"programs": 1, "attempted": 1, "added": 1, "excluded": 0}

            def fake_export(_fidb, output, _language):
                output.write_text("{}\n", encoding="utf-8")
                return {
                    "records": 1,
                    "unique_full_hashes": 1,
                    "unique_signatures": 1,
                }

            with (
                patch(
                    "fidb_poc.pipeline.find_ghidra",
                    return_value=(headless, root / "ghidra"),
                ),
                patch(
                    "fidb_poc.pipeline.java_identity",
                    return_value=(Path("/usr/bin/java"), "21.0.1", 21),
                ),
                patch("fidb_poc.pipeline.pyghidra_identity", return_value="3.1.0"),
                patch("fidb_poc.pipeline.ghidra_fid.ensure_started"),
                patch(
                    "fidb_poc.pipeline.ghidra_fid.build_library_fidb",
                    side_effect=fake_build,
                ) as build,
                patch(
                    "fidb_poc.pipeline.ghidra_fid.export_fid_signatures",
                    side_effect=fake_export,
                ),
            ):
                _populate_group(configuration, root, route, treatment, records, objects)

            self.assertEqual(build.call_args.kwargs["language"], route.ghidra_language)
            self.assertEqual(
                build.call_args.kwargs["compiler_spec"], route.ghidra_compiler_spec
            )
            record = records[key]
            self.assertEqual(record.status, "complete")
            self.assertEqual(record.fid_added, 1)
            self.assertEqual(record.fid_unique_signatures, 1)
            self.assertEqual(record.pyghidra_version, "3.1.0")
            self.assertTrue((root / record.fidb_path).is_file())
            self.assertTrue((root / record.fid_signatures_path).is_file())

    def test_execute_rejects_symlinked_generated_root(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.toml", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_directory = root / "src"
            source_directory.mkdir()
            marker = source_directory / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            (root / "work").symlink_to(source_directory, target_is_directory=True)

            with self.assertRaisesRegex(PipelineError, "generated root"):
                execute(configuration, root)

            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            self.assertEqual(list(source_directory.iterdir()), [marker])

    def test_execute_writes_manifest_then_raises_for_failed_cell(self):
        source_root = Path(__file__).resolve().parents[1]
        configuration = load_configuration(
            source_root / "worker.toml", request_override=("zlib",)
        )
        configuration = select_configuration(
            configuration,
            route_ids=("linux-x86_64-gnu-gcc",),
            treatment_ids=None,
            profile="smoke",
        )
        detection = Detection(
            build_system="autoconf",
            evidence=("configure",),
            languages=("C",),
            project_markers=("configure",),
        )
        failed = BuildRecord(
            library="zlib",
            version="1.3.1",
            route="linux-x86_64-gnu-gcc",
            treatment="baseline_o2",
            status="build_failed",
            error="compiler failed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = root / "artifacts/libs/fidb/stale.fidb"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")
            progress = []
            with (
                patch("fidb_poc.pipeline.download_library", return_value=root / "a"),
                patch("fidb_poc.pipeline.extract_source", return_value=root / "source"),
                patch("fidb_poc.pipeline.detect_project", return_value=detection),
                patch("fidb_poc.pipeline.build_library", return_value=(failed, [])),
                patch("fidb_poc.pipeline.populate_fidbs"),
                self.assertRaisesRegex(PipelineError, "did not complete"),
            ):
                execute(configuration, root, progress=progress.append)

            manifest = root / "artifacts/libs/fidb_manifest.csv"
            self.assertTrue(manifest.is_file())
            self.assertFalse(stale.exists())
            self.assertIn("Result: build_failed=1", progress)
            self.assertIn(f"Manifest: {manifest}", progress)


if __name__ == "__main__":
    unittest.main()
