import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fidb_poc.adapters import (
    AdapterError,
    build_commands,
    detect_project,
    linked_output_command,
)
from fidb_poc.config import Library, Route, Treatment


def library() -> Library:
    return Library(
        name="example",
        version="1",
        url="https://example.invalid/example.tar.gz",
        sha256="a" * 64,
        source_directory="example-1",
        project_markers=("example.h", "configure"),
        allowed_build_systems=("autoconf", "make"),
        preferred_build_system="autoconf",
        static_archives=("libexample.a",),
    )


def route() -> Route:
    return Route(
        id="linux-x86_64-gnu-gcc",
        target_os="linux",
        architecture="x86_64",
        binary_format="ELF",
        compiler=("/usr/bin/gcc",),
        archiver=("/usr/bin/ar",),
        ranlib=("/usr/bin/ranlib",),
        compiler_flags=("-O2", "-fPIC", "-fno-lto", "-fno-omit-frame-pointer"),
        object_file_markers=("ELF",),
        linked_suffix=".so",
        linked_file_markers=("ELF", "shared object"),
        ghidra_language="x86:LE:64:default",
    )


class AdapterTests(unittest.TestCase):
    def test_detection_uses_files_not_library_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "example.h").write_text("", encoding="utf-8")
            (root / "configure").write_text("", encoding="utf-8")
            (root / "Makefile").write_text("", encoding="utf-8")
            (root / "implementation.c").write_text("", encoding="utf-8")
            detected = detect_project(library(), root)
            self.assertEqual(detected.build_system, "autoconf")
            self.assertEqual(detected.languages, ("C",))
            self.assertIn("configure", detected.evidence)

    def test_detection_fails_when_source_identity_marker_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "configure").write_text("", encoding="utf-8")
            with self.assertRaisesRegex(AdapterError, "source identity check failed"):
                detect_project(library(), root)

    def test_adapter_emits_fixed_command_shape(self):
        commands = build_commands(
            "autoconf", route=route(), compiler_flags=("-O0",), jobs=4
        )
        self.assertEqual(commands[0], ("sh", "configure", "--static"))
        self.assertEqual(
            commands[1],
            (
                "make",
                "-j4",
                "libz.a",
                "AR=/usr/bin/ar",
                "ARFLAGS=rc",
                "RANLIB=/usr/bin/ranlib",
            ),
        )

    def test_make_adapter_emits_fixed_command_shape(self):
        commands = build_commands(
            "make",
            route=route(),
            compiler_flags=("-O2", "-fPIC", "-fno-lto"),
            jobs=3,
        )
        self.assertEqual(
            commands,
            (
                (
                    "make",
                    "-j3",
                    "libbz2.a",
                    "CC=/usr/bin/gcc",
                    (
                        "CFLAGS=-Wall -Winline -D_FILE_OFFSET_BITS=64 "
                        "-O2 -fPIC -fno-lto"
                    ),
                    "AR=/usr/bin/ar",
                    "RANLIB=/usr/bin/ranlib",
                ),
            ),
        )

    def test_link_adapter_materialises_archive_without_raw_recipe_commands(self):
        treatment = Treatment(
            id="linked_demo",
            factor="baseline",
            description="linked-output adapter fixture",
            remove_flags=(),
            append_flags=(),
            supported_routes=(),
            phase="link",
        )
        command = linked_output_command(
            route=route(),
            treatment=treatment,
            archives=(Path("/work/libexample.a"),),
            output=Path("/work/libexample.so"),
        )
        self.assertIn("-shared", command)
        self.assertIn("-nostdlib", command)
        self.assertIn("-Wl,--whole-archive", command)
        self.assertIn("/work/libexample.a", command)
        self.assertEqual(command[-2:], ("-o", "/work/libexample.so"))

    def test_link_adapter_rejects_routes_outside_the_linux_poc(self):
        treatment = Treatment(
            id="linked_demo",
            factor="baseline",
            description="linked-output adapter fixture",
            remove_flags=(),
            append_flags=(),
            supported_routes=(),
            phase="link",
        )
        unsupported = replace(route(), target_os="macos")
        with self.assertRaisesRegex(AdapterError, "Linux PoC"):
            linked_output_command(
                route=unsupported,
                treatment=treatment,
                archives=(Path("/work/libexample.a"),),
                output=Path("/work/libexample.dylib"),
            )


if __name__ == "__main__":
    unittest.main()
