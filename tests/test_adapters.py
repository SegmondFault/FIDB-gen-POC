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
    prepare_build_workspace,
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
        self.assertEqual(commands[1], ("make", "-j7", "-C", "lib", "libnghttp2.la"))

    def test_gettext_uses_adjacent_cxx_driver_for_configure_probes(self):
        environment = build_environment(
            "gettext-autoconf", route=route(), compiler_flags=("-O2",)
        )

        self.assertEqual(environment["CXX"], "/usr/bin/g++")

    def test_gmp_cross_build_uses_a_native_host_generator_compiler(self):
        windows = replace(route(), target_os="windows")

        environment = build_environment(
            "gmp-autoconf", route=windows, compiler_flags=("-O2",)
        )

        self.assertEqual(environment["CC_FOR_BUILD"], "/usr/bin/cc")
        self.assertEqual(environment["CC"], "/usr/bin/gcc")

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

    def test_freetype_adapter_disables_unpinned_optional_dependencies(self):
        commands = build_commands(
            "freetype-autoconf", route=route(), compiler_flags=("-Os",), jobs=6
        )

        self.assertIn("--with-zlib=no", commands[0])
        self.assertIn("--with-harfbuzz=no", commands[0])
        self.assertEqual(commands[1], ("make", "-j6", "all"))

    def test_libtiff_adapter_disables_external_codec_dependencies(self):
        commands = build_commands(
            "libtiff-autoconf", route=route(), compiler_flags=("-O2",), jobs=5
        )

        self.assertIn("--disable-zlib", commands[0])
        self.assertIn("--disable-jpeg", commands[0])
        self.assertIn("--disable-zstd", commands[0])
        self.assertEqual(commands[1], ("make", "-j5", "-C", "libtiff", "libtiff.la"))

    def test_new_autoconf_adapters_are_static_and_dependency_bounded(self):
        libffi = build_commands(
            "libffi-autoconf", route=route(), compiler_flags=("-O2",), jobs=4
        )
        libxml2 = build_commands(
            "libxml2-autoconf", route=route(), compiler_flags=("-Os",), jobs=3
        )

        self.assertIn("--disable-multi-os-directory", libffi[0])
        self.assertEqual(libffi[1], ("make", "-j4", "all"))
        self.assertIn("--without-iconv", libxml2[0])
        self.assertIn("--without-icu", libxml2[0])
        self.assertIn("--without-zlib", libxml2[0])
        self.assertEqual(libxml2[1], ("make", "-j3", "libxml2.la"))

    def test_new_cmake_adapters_select_only_static_library_targets(self):
        libuv = build_commands(
            "libuv-cmake", route=route(), compiler_flags=("-O2",), jobs=4
        )
        openjpeg = build_commands(
            "openjpeg-cmake", route=route(), compiler_flags=("-O2",), jobs=4
        )
        opus = build_commands(
            "opus-cmake", route=route(), compiler_flags=("-O2",), jobs=4
        )

        self.assertIn("-DLIBUV_BUILD_SHARED=OFF", libuv[0])
        self.assertEqual(libuv[1][-1], "uv_a")
        self.assertIn("-DBUILD_CODEC=OFF", openjpeg[0])
        self.assertEqual(openjpeg[1][-1], "openjp2")
        self.assertIn("-DOPUS_STACK_PROTECTOR=OFF", opus[0])
        self.assertEqual(opus[1][-1], "opus")

    def test_priority_autoconf_adapters_are_library_only_and_dependency_bounded(self):
        curl = build_commands(
            "curl-autoconf", route=route(), compiler_flags=("-O2",), jobs=6
        )
        ncurses = build_commands(
            "ncurses-autoconf", route=route(), compiler_flags=("-Os",), jobs=4
        )
        pcap = build_commands(
            "libpcap-autoconf", route=route(), compiler_flags=("-O0",), jobs=3
        )

        self.assertIn("--without-ssl", curl[0])
        self.assertIn("--without-zlib", curl[0])
        self.assertIn("--disable-ldap", curl[0])
        self.assertIn("--disable-ldaps", curl[0])
        self.assertEqual(curl[1], ("make", "-j6", "-C", "lib", "libcurl.la"))
        self.assertIn("--with-termlib", ncurses[0])
        self.assertEqual(ncurses[1], ("make", "-j4", "libs"))
        self.assertIn("--without-libnl", pcap[0])
        self.assertEqual(pcap[1], ("make", "-j3", "libpcap.a"))

    def test_priority_cmake_adapters_pin_inputs_and_static_targets(self):
        source_root = Path("/work/priority").resolve()
        opencl = build_commands(
            "opencl-loader-cmake",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        protobuf = build_commands(
            "protobuf-cmake",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        mbedtls = build_commands(
            "mbedtls-cmake",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        wolfssl = build_commands(
            "wolfssl-cmake",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )

        self.assertIn("-DOPENCL_ICD_LOADER_BUILD_SHARED_LIBS=OFF", opencl[0])
        self.assertIn("-DHAVE_SECURE_GETENV=OFF", opencl[0])
        self.assertIn("-DHAVE___SECURE_GETENV=OFF", opencl[0])
        self.assertIn("-DCMAKE_STATIC_LIBRARY_PREFIX=lib", opencl[0])
        self.assertIn(
            f"-DOPENCL_ICD_LOADER_HEADERS_DIR={source_root}/fidb-inputs/opencl-headers-2026.05.29",
            opencl[0],
        )
        self.assertIn(
            f"-DFETCHCONTENT_SOURCE_DIR_ABSL={source_root}/fidb-inputs/abseil-cpp-20250512.1",
            protobuf[0],
        )
        self.assertEqual(protobuf[1][-1], "libprotobuf")
        self.assertEqual(mbedtls[1][-3:], ("tfpsacrypto", "mbedx509", "mbedtls"))
        self.assertIn("-DHAVE_GMTIME_R=OFF", wolfssl[0])

    def test_priority_specialist_adapters_are_bounded_and_reproducible(self):
        source_root = Path("/work/priority").resolve()
        krb5 = build_commands(
            "krb5-autoconf",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        comerr = build_commands(
            "e2fsprogs-comerr-autoconf",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        libedit = build_commands(
            "libedit-autoconf",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        libssh2 = build_commands(
            "libssh2-autoconf",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        musl = build_commands(
            "musl-cross",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )
        perl = build_commands(
            "perl-native",
            route=route(),
            compiler_flags=("-O2",),
            jobs=4,
            source_root=source_root,
        )

        self.assertIn("--without-system-verto", krb5[1])
        self.assertEqual(krb5[-1][-1], "fidb-build/lib/libkrb5.a")
        self.assertIn("--disable-fuse2fs", comerr[0])
        self.assertEqual(comerr[-1][-1], "lib/libcom_err.a")
        self.assertIn("vi.h", libedit[-2])
        self.assertIn("-DWOLFSSL_OPENSSLEXTRA=yes", libssh2[0])
        self.assertIn("-DBUILD_SHARED_LIBS=OFF", libssh2[0])
        self.assertIn("-DHAVE_GMTIME_R=OFF", libssh2[0])
        self.assertEqual(musl[0][1], "./configure")
        self.assertIn("-Dlocincpth=/nonexistent", perl[0])

    def test_boringssl_adapter_uses_only_the_pinned_generator_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary).resolve()
            (source_root / "err_data.c").write_text("generated", encoding="utf-8")
            (source_root / "src").mkdir()
            (source_root / "src/CMakeLists.txt").write_text(
                'set(C_CXX_FLAGS "-Werror -Wall")\n', encoding="utf-8"
            )
            prepare_build_workspace(
                "boringssl-cmake",
                route=route(),
                compiler_flags=("-O2",),
                source_root=source_root,
            )
            commands = build_commands(
                "boringssl-cmake",
                route=route(),
                compiler_flags=("-O2",),
                jobs=4,
                source_root=source_root,
            )
            shim = (source_root / "fidb-boringssl-go").read_text()
            gtest_placeholder = (
                source_root / "src/third_party/googletest/src/gtest-all.cc"
            ).read_text()
            warning_policy = (source_root / "src/CMakeLists.txt").read_text()

        self.assertEqual(commands[0][1:3], ("-S", "src"))
        self.assertIn(f"-DGO_EXECUTABLE={source_root}/fidb-boringssl-go", commands[0])
        self.assertEqual(commands[1][-2:], ("crypto", "ssl"))
        self.assertIn("err_data_generate.go", shim)
        self.assertIn("target is not built", gtest_placeholder)
        self.assertEqual(warning_policy, 'set(C_CXX_FLAGS "-Wall")\n')

    def test_harfbuzz_cmake_adapter_pins_compilers_and_library_targets(self):
        commands = build_commands(
            "harfbuzz-cmake",
            route=route(),
            compiler_flags=("-O0", "-fPIC"),
            jobs=8,
        )
        environment = build_environment(
            "harfbuzz-cmake", route=route(), compiler_flags=("-O0", "-fPIC")
        )

        self.assertIn("-DCMAKE_SYSTEM_NAME=Linux", commands[0])
        self.assertIn("-DCMAKE_C_COMPILER=/usr/bin/gcc", commands[0])
        self.assertIn("-DCMAKE_CXX_COMPILER=/usr/bin/g++", commands[0])
        self.assertIn("-DCMAKE_CXX_FLAGS=-O0 -fPIC", commands[0])
        self.assertIn("-DCMAKE_DISABLE_FIND_PACKAGE_PNG=ON", commands[0])
        self.assertIn("-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=ON", commands[0])
        self.assertIn("-DHB_BUILD_GPU_DEMO=OFF", commands[0])
        self.assertEqual(
            commands[1][0:7],
            (
                "cmake",
                "--build",
                "fidb-build",
                "--parallel",
                "8",
                "--target",
                "harfbuzz",
            ),
        )
        self.assertIn("harfbuzz-gpu", commands[1])
        self.assertEqual(environment["CXX"], "/usr/bin/g++")

    def test_cmake_adapter_maps_android_abi_without_host_execution(self):
        ndk_root = Path("/reviewed/android-ndk-r29")
        android = replace(
            route(),
            target_os="android",
            architecture="i686",
            compiler=(
                str(
                    ndk_root
                    / "toolchains/llvm/prebuilt/linux-x86_64/bin"
                    / "i686-linux-android21-clang"
                ),
            ),
        )

        commands = build_commands(
            "brotli-cmake", route=android, compiler_flags=("-O2",), jobs=4
        )

        self.assertIn("-DCMAKE_SYSTEM_NAME=Android", commands[0])
        self.assertIn("-DCMAKE_ANDROID_ARCH_ABI=x86", commands[0])
        self.assertNotIn("-DCMAKE_SYSTEM_PROCESSOR=i686", commands[0])
        self.assertIn("-DCMAKE_SYSTEM_VERSION=21", commands[0])
        self.assertIn("-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY", commands[0])

    def test_libjpeg_adapter_uses_reproducible_portable_static_shape(self):
        commands = build_commands(
            "libjpeg-turbo-cmake", route=route(), compiler_flags=("-O3",), jobs=3
        )

        self.assertIn("-DENABLE_SHARED=OFF", commands[0])
        self.assertIn("-DWITH_SIMD=OFF", commands[0])
        self.assertIn("-DWITH_SYSTEM_ZLIB=OFF", commands[0])
        self.assertEqual(commands[1][-2:], ("jpeg-static", "turbojpeg-static"))

    def test_libpng_adapter_builds_pinned_route_matched_zlib_first(self):
        source_root = Path("/work/libpng").resolve()

        commands = build_commands(
            "libpng-cmake",
            route=route(),
            compiler_flags=("-Os", "-fPIC"),
            jobs=5,
            source_root=source_root,
        )

        self.assertEqual(len(commands), 5)
        self.assertIn(
            f"-DCMAKE_INSTALL_PREFIX={source_root}/fidb-deps/zlib-install",
            commands[0],
        )
        self.assertIn("-DCMAKE_C_COMPILER=/usr/bin/gcc", commands[0])
        self.assertIn("-DCMAKE_C_FLAGS=-Os -fPIC", commands[0])
        self.assertEqual(
            commands[1][0:3],
            ("cmake", "--build", f"{source_root}/fidb-deps/zlib-build"),
        )
        self.assertEqual(commands[2][0:2], ("cmake", "--install"))
        self.assertIn(f"-DZLIB_ROOT={source_root}/fidb-deps/zlib-install", commands[3])
        self.assertEqual(commands[4][-2:], ("--target", "png_static"))

    def test_libpng_adapter_rejects_an_unbound_dependency_workspace(self):
        with self.assertRaisesRegex(AdapterError, "absolute source root"):
            build_commands(
                "libpng-cmake",
                route=route(),
                compiler_flags=("-O2",),
                jobs=4,
            )

    def test_glib_adapter_writes_target_machine_and_uses_offline_fallbacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary).resolve()
            prepare_build_workspace(
                "glib-meson",
                route=route(),
                compiler_flags=("-O3", "-fPIC"),
                source_root=source_root,
            )
            commands = build_commands(
                "glib-meson",
                route=route(),
                compiler_flags=("-O3", "-fPIC"),
                jobs=6,
                source_root=source_root,
            )
            cross_file = (source_root / "fidb-cross.ini").read_text()

        self.assertIn("c = ['/usr/bin/gcc']", cross_file)
        self.assertIn("cpp = ['/usr/bin/g++']", cross_file)
        self.assertIn("system = 'linux'", cross_file)
        self.assertIn("cpu_family = 'x86_64'", cross_file)
        self.assertIn("needs_exe_wrapper = true", cross_file)
        self.assertIn("c_args = ['-O3', '-fPIC']", cross_file)
        self.assertIn("--wrap-mode=forcefallback", commands[0])
        self.assertIn("-Dtests=false", commands[0])
        self.assertEqual(
            commands[1][-4:],
            ("glib-2.0", "gmodule-2.0", "gobject-2.0", "gio-2.0"),
        )

    def test_glib_cross_file_preserves_target_endianness(self):
        big_endian = replace(route(), architecture="mips")
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary).resolve()
            prepare_build_workspace(
                "glib-meson",
                route=big_endian,
                compiler_flags=("-O2",),
                source_root=source_root,
            )
            cross_file = (source_root / "fidb-cross.ini").read_text()

        self.assertIn("cpu_family = 'mips'", cross_file)
        self.assertIn("endian = 'big'", cross_file)

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
        self.assertEqual(commands[2], ("make", "-j4", "libreadline.a", "libhistory.a"))

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
