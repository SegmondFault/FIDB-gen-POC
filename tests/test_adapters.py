import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fidb_poc.adapters import (
    AdapterError,
    build_commands,
    build_environment,
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
        compiler_family="gcc",
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

    def test_specialized_detection_requires_every_adapter_marker(self):
        specialized = replace(
            library(),
            project_markers=("configure", "sqlite3.c", "sqlite3.h"),
            allowed_build_systems=("autoconf", "sqlite-autoconf"),
            preferred_build_system="sqlite-autoconf",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("configure", "sqlite3.c", "sqlite3.h"):
                (root / name).write_text("", encoding="utf-8")

            detected = detect_project(specialized, root)

        self.assertEqual(detected.build_system, "sqlite-autoconf")
        self.assertIn("sqlite3.c", detected.evidence)

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

    def test_openssl_adapter_selects_reviewed_target_and_static_libraries(self):
        commands = build_commands(
            "openssl-configure", route=route(), compiler_flags=("-O2",), jobs=8
        )

        self.assertEqual(
            commands[0],
            (
                "perl",
                "Configure",
                "linux-x86_64",
                "no-shared",
                "no-tests",
                "no-docs",
                "no-module",
            ),
        )
        self.assertEqual(commands[1], ("make", "-j8", "build_libs"))

    def test_openssl_android_adapter_pins_abi_api_and_ndk_environment(self):
        ndk_root = Path("/reviewed/android-ndk-r29")
        compiler = (
            str(
                ndk_root
                / "toolchains/llvm/prebuilt/linux-x86_64/bin"
                / "aarch64-linux-android21-clang"
            ),
        )
        android = replace(
            route(),
            id="android-arm64-ndk-r29-clang-api21",
            target_os="android",
            architecture="aarch64",
            compiler=compiler,
        )

        commands = build_commands(
            "openssl-configure", route=android, compiler_flags=("-O2",), jobs=8
        )
        environment = build_environment(
            "openssl-configure", route=android, compiler_flags=("-O2",)
        )

        self.assertEqual(commands[0][2], "android-arm64")
        self.assertIn("-D__ANDROID_API__=21", commands[0])
        self.assertEqual(environment["ANDROID_NDK_ROOT"], str(ndk_root))
        self.assertTrue(
            environment["PATH"].startswith(f"{compiler[0].rsplit('/', 1)[0]}:")
        )

    def test_specialized_autoconf_adapter_pins_host_options_and_target(self):
        commands = build_commands(
            "nghttp2-autoconf", route=route(), compiler_flags=("-O2",), jobs=7
        )

        self.assertEqual(
            commands[0],
            (
                "sh",
                "configure",
                "--host=x86_64-linux-gnu",
                "--disable-shared",
                "--enable-static",
                "--disable-app",
                "--disable-examples",
                "--disable-hpack-tools",
                "--disable-failmalloc",
            ),
        )
        self.assertEqual(
            commands[1], ("make", "-j7", "-C", "lib", "libnghttp2.la")
        )

    def test_gettext_uses_adjacent_cxx_driver_for_configure_probes(self):
        environment = build_environment(
            "gettext-autoconf", route=route(), compiler_flags=("-O2",)
        )

        self.assertEqual(environment["CXX"], "/usr/bin/g++")

    def test_specialized_autoconf_adapter_maps_android_host(self):
        ndk_root = Path("/reviewed/android-ndk-r29")
        android = replace(
            route(),
            target_os="android",
            architecture="arm",
            compiler=(
                str(
                    ndk_root
                    / "toolchains/llvm/prebuilt/linux-x86_64/bin"
                    / "armv7a-linux-androideabi21-clang"
                ),
            ),
        )

        commands = build_commands(
            "sqlite-autoconf", route=android, compiler_flags=("-O2",), jobs=2
        )
        environment = build_environment(
            "sqlite-autoconf", route=android, compiler_flags=("-O2",)
        )

        self.assertIn("--host=arm-linux-androideabi", commands[0])
        self.assertEqual(environment["ANDROID_NDK_ROOT"], str(ndk_root))

    def test_fixed_make_adapters_keep_treatment_flags_and_platform(self):
        windows = replace(route(), target_os="windows")

        lz4 = build_commands(
            "lz4-make", route=windows, compiler_flags=("-O0", "-fPIC"), jobs=4
        )
        zstd = build_commands(
            "zstd-make", route=windows, compiler_flags=("-Os",), jobs=3
        )

        self.assertIn("CFLAGS=-O0 -fPIC", lz4[0])
        self.assertIn("TARGET_OS=Windows_NT", lz4[0])
        self.assertIn("BUILD_DIR=obj/fidb", zstd[0])
        self.assertIn("obj/fidb/static/libzstd.a", zstd[0])
        self.assertIn("TARGET_SYSTEM=Windows_NT", zstd[0])

    def test_readline_windows_workaround_is_narrow_and_fixed(self):
        windows = replace(route(), target_os="windows")

        commands = build_commands(
            "readline-autoconf",
            route=windows,
            compiler_flags=("-O2", "-fno-lto"),
            jobs=4,
        )

        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[1][0:3], ("make", "terminal.o", "rltty.o"))
        self.assertIn("-include windows.h", commands[1][3])
        self.assertIn("-Dwinsize=_CONSOLE_SCREEN_BUFFER_INFO", commands[1][3])
        self.assertEqual(
            commands[2], ("make", "-j4", "libreadline.a", "libhistory.a")
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
        with self.assertRaisesRegex(AdapterError, "ELF PoC"):
            linked_output_command(
                route=unsupported,
                treatment=treatment,
                archives=(Path("/work/libexample.a"),),
                output=Path("/work/libexample.dylib"),
            )


if __name__ == "__main__":
    unittest.main()
