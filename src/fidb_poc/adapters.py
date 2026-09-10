from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .config import Library, Route, Treatment


class AdapterError(RuntimeError):
    pass


@dataclass(frozen=True)
class Detection:
    build_system: str
    evidence: tuple[str, ...]
    languages: tuple[str, ...]
    project_markers: tuple[str, ...]


BUILD_MARKERS = {
    "openssl-configure": ("Configure",),
    "boringssl-cmake": ("src/CMakeLists.txt", "src/include/openssl/ssl.h"),
    "harfbuzz-cmake": ("CMakeLists.txt", "src/hb.h"),
    "brotli-cmake": ("CMakeLists.txt", "c/include/brotli/encode.h"),
    "libjpeg-turbo-cmake": ("CMakeLists.txt", "src/jpeglib.h"),
    "libpng-cmake": ("CMakeLists.txt", "png.h"),
    "glib-meson": ("meson.build", "glib/glib.h"),
    "freetype-autoconf": ("configure", "include/freetype/freetype.h"),
    "expat-autoconf": ("configure", "lib/expat.h"),
    "libunistring-autoconf": ("configure", "lib/unistr.in.h"),
    "libtiff-autoconf": ("configure", "libtiff/tiff.h"),
    "libffi-autoconf": ("configure", "include/ffi.h.in"),
    "libxml2-autoconf": ("configure", "include/libxml/parser.h"),
    "curl-autoconf": ("configure", "include/curl/curl.h"),
    "jansson-autoconf": ("configure", "src/jansson.h"),
    "ncurses-autoconf": ("configure", "include/curses.h.in"),
    "libmicrohttpd-autoconf": ("configure", "src/include/microhttpd.h"),
    "hwloc-autoconf": ("configure", "include/hwloc.h"),
    "libpcap-autoconf": ("configure", "pcap/pcap.h"),
    "krb5-autoconf": ("src/configure", "src/include/krb5.h"),
    "e2fsprogs-comerr-autoconf": ("configure", "lib/et/com_err.h"),
    "libedit-autoconf": ("configure", "src/histedit.h"),
    "libssh2-autoconf": ("configure", "include/libssh2.h"),
    "musl-cross": ("configure", "src/internal/libc.h"),
    "perl-native": ("Configure", "perl.h"),
    "scotch-cmake": ("CMakeLists.txt", "src/libscotch/CMakeLists.txt"),
    "opencl-loader-cmake": ("CMakeLists.txt", "loader/icd.c"),
    "protobuf-cmake": ("CMakeLists.txt", "src/google/protobuf/descriptor.h"),
    "mbedtls-cmake": ("CMakeLists.txt", "include/mbedtls/ssl.h"),
    "wolfssl-cmake": ("CMakeLists.txt", "wolfssl/ssl.h"),
    "libuv-cmake": ("CMakeLists.txt", "include/uv.h"),
    "openjpeg-cmake": ("CMakeLists.txt", "src/lib/openjp2/openjpeg.h"),
    "opus-cmake": ("CMakeLists.txt", "include/opus.h"),
    "sqlite-autoconf": ("configure", "sqlite3.c", "sqlite3.h"),
    "xz-autoconf": ("configure", "src/liblzma/api/lzma.h"),
    "pcre2-autoconf": ("configure", "src/pcre2.h.in"),
    "gettext-autoconf": ("configure", "gettext-runtime/intl/libgnuintl.in.h"),
    "nghttp2-autoconf": (
        "configure",
        "lib/includes/nghttp2/nghttp2.h",
    ),
    "readline-autoconf": ("configure", "readline.h"),
    "gmp-autoconf": ("configure", "gmp-h.in"),
    "zstd-make": ("Makefile", "lib/zstd.h"),
    "lz4-make": ("Makefile", "lib/lz4.h"),
    "autoconf": ("configure",),
    "cmake": ("CMakeLists.txt",),
    "meson": ("meson.build",),
    "make": ("Makefile",),
    "cargo": ("Cargo.toml",),
    "go": ("go.mod",),
}

LANGUAGE_SUFFIXES = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".rs": "Rust",
    ".go": "Go",
}


def _exact_exists(root: Path, relative: str) -> bool:
    path = root / relative
    parent = path.parent
    if not parent.is_dir():
        return False
    return path.name in {entry.name for entry in parent.iterdir()}


def detect_project(library: Library, source_root: Path) -> Detection:
    missing = [
        marker
        for marker in library.project_markers
        if not _exact_exists(source_root, marker)
    ]
    if missing:
        raise AdapterError(
            f"source identity check failed for {library.identifier}; "
            f"missing markers: {', '.join(missing)}"
        )

    detected = []
    evidence = []
    for build_system, markers in BUILD_MARKERS.items():
        present = [marker for marker in markers if _exact_exists(source_root, marker)]
        if len(present) == len(markers):
            detected.append(build_system)
            evidence.extend(present)
    disallowed = set(detected) - set(library.allowed_build_systems)
    if disallowed:
        raise AdapterError(
            f"unexpected build systems for {library.identifier}: {sorted(disallowed)}"
        )
    if library.preferred_build_system not in detected:
        raise AdapterError(
            f"preferred adapter {library.preferred_build_system!r} was not detected "
            f"for {library.identifier}; detected={detected}"
        )

    languages = sorted(
        {
            LANGUAGE_SUFFIXES[path.suffix.lower()]
            for path in source_root.rglob("*")
            if path.is_file() and path.suffix.lower() in LANGUAGE_SUFFIXES
        }
    )
    if not languages:
        raise AdapterError(f"no supported source language detected in {source_root}")
    return Detection(
        build_system=library.preferred_build_system,
        evidence=tuple(sorted(set(evidence))),
        languages=tuple(languages),
        project_markers=library.project_markers,
    )


def tool_text(command: tuple[str, ...]) -> str:
    return " ".join(command)


def _android_ndk_root(route: Route) -> Path:
    """Recover the reviewed NDK root from a qualified target wrapper path."""

    compiler = Path(route.compiler[0])
    marker = ("toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    parts = compiler.parts
    for index in range(len(parts) - len(marker)):
        if parts[index : index + len(marker)] == marker:
            return Path(*parts[:index])
    raise AdapterError(
        f"Android route {route.id} compiler is not inside a Linux NDK toolchain"
    )


def _configure_host(route: Route) -> str:
    """Return the reviewed GNU host tuple for a non-Apple C route."""

    hosts = {
        ("linux", "x86_64"): "x86_64-linux-gnu",
        ("linux", "arm"): "arm-linux-gnueabihf",
        ("linux", "aarch64"): "aarch64-linux-gnu",
        ("linux", "mips"): "mips-linux-gnu",
        ("linux", "mipsel"): "mipsel-linux-gnu",
        ("linux", "powerpc"): "powerpc-linux-gnu",
        ("linux", "sh4"): "sh4-linux-gnu",
        ("linux", "m68k"): "m68k-linux-gnu",
        ("windows", "x86_64"): "x86_64-w64-mingw32",
        ("android", "aarch64"): "aarch64-linux-android",
        ("android", "arm"): "arm-linux-androideabi",
        ("android", "x86_64"): "x86_64-linux-android",
        ("android", "i686"): "i686-linux-android",
    }
    host = hosts.get((route.target_os, route.architecture))
    if host is None:
        raise AdapterError(
            f"no reviewed configure host for {route.target_os}/{route.architecture}"
        )
    return host


def _cxx_compiler(route: Route) -> str:
    """Derive the adjacent C++ driver used only by configure-time probes."""

    command = list(route.compiler)
    executable = Path(command[0])
    if executable.name.endswith("gcc"):
        executable = executable.with_name(f"{executable.name[:-3]}g++")
    elif executable.name.endswith("clang"):
        executable = executable.with_name(f"{executable.name}++")
    else:
        raise AdapterError(
            f"cannot derive configure-time C++ driver for route {route.id}"
        )
    command[0] = str(executable)
    return tool_text(tuple(command))


def _meson_values(values: tuple[str, ...]) -> str:
    escaped = [value.replace("\\", "\\\\").replace("'", "\\'") for value in values]
    return "[" + ", ".join(f"'{value}'" for value in escaped) + "]"


def prepare_build_workspace(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
    source_root: Path,
) -> None:
    """Write fixed adapter-owned files which cannot be supplied by recipes."""

    if build_system == "boringssl-cmake":
        generated = source_root / "err_data.c"
        if not generated.is_file():
            raise AdapterError("BoringSSL source lacks its pinned err_data.c")
        # This pinned Android source snapshot promotes all warnings to errors.
        # Cross sysroots can legitimately provide newer ARM HWCAP definitions
        # than the snapshot, producing harmless macro-redefinition warnings.
        # Remove only the exact upstream -Werror token: warning policy must not
        # make an otherwise valid compilation route unusable.
        cmake_lists = source_root / "src/CMakeLists.txt"
        cmake_text = cmake_lists.read_text(encoding="utf-8")
        warning_policy = 'set(C_CXX_FLAGS "-Werror '
        if cmake_text.count(warning_policy) != 1:
            raise AdapterError("BoringSSL warning-policy patch no longer applies")
        cmake_lists.write_text(
            cmake_text.replace(warning_policy, 'set(C_CXX_FLAGS "', 1),
            encoding="utf-8",
        )
        # Debian's source-only BoringSSL archive omits googletest, while the
        # upstream CMake graph still declares (but need not build) its test
        # target.  A source-less translation unit lets CMake generate the
        # graph without fetching or compiling an unpinned dependency.
        gtest = source_root / "src/third_party/googletest/src/gtest-all.cc"
        gtest.parent.mkdir(parents=True, exist_ok=True)
        gtest.write_text(
            "// FIDB adapter placeholder: the boringssl_gtest target is not built.\n",
            encoding="utf-8",
        )
        shim = source_root / "fidb-boringssl-go"
        shim.write_text(
            "#!/bin/sh\n"
            'if [ "$#" -eq 2 ] && [ "$1" = run ] && '
            '[ "$2" = err_data_generate.go ]; then\n'
            '  exec cat "$(dirname "$0")/err_data.c"\n'
            "fi\n"
            'echo "unsupported BoringSSL generator invocation: $*" >&2\n'
            "exit 64\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        return
    if build_system == "libedit-autoconf":
        readline = source_root / "src/readline.c"
        text = readline.read_text(encoding="utf-8")
        original = """char *
username_completion_function(const char *text, int state)
{
	struct passwd *pass = NULL;
"""
        replacement = """char *
username_completion_function(const char *text, int state)
{
#if defined(__ANDROID__)
	(void)text;
	(void)state;
	return NULL;
#else
	struct passwd *pass = NULL;
"""
        ending = """	return strdup(pass->pw_name);
}


/*
 * el-compatible wrapper to send TSTP on ^Z
 */
"""
        patched_ending = """	return strdup(pass->pw_name);
#endif
}


/*
 * el-compatible wrapper to send TSTP on ^Z
 */
"""
        if text.count(original) != 1 or text.count(ending) != 1:
            raise AdapterError("libedit Android compatibility patch no longer applies")
        readline.write_text(
            text.replace(original, replacement, 1).replace(ending, patched_ending, 1),
            encoding="utf-8",
        )
        return
    if build_system != "glib-meson":
        return
    machines = {
        ("linux", "x86_64"): ("linux", "x86_64", "x86_64", "little"),
        ("linux", "arm"): ("linux", "arm", "armv7", "little"),
        ("linux", "aarch64"): ("linux", "aarch64", "aarch64", "little"),
        ("linux", "mips"): ("linux", "mips", "mips", "big"),
        ("linux", "mipsel"): ("linux", "mips", "mipsel", "little"),
        ("linux", "powerpc"): ("linux", "ppc", "ppc", "big"),
        ("linux", "sh4"): ("linux", "sh4", "sh4", "little"),
        ("linux", "m68k"): ("linux", "m68k", "m68k", "big"),
        ("windows", "x86_64"): ("windows", "x86_64", "x86_64", "little"),
        ("android", "aarch64"): ("android", "aarch64", "aarch64", "little"),
        ("android", "arm"): ("android", "arm", "armv7", "little"),
        ("android", "x86_64"): ("android", "x86_64", "x86_64", "little"),
        ("android", "i686"): ("android", "x86", "i686", "little"),
    }
    machine = machines.get((route.target_os, route.architecture))
    if machine is None:
        raise AdapterError(
            f"no reviewed Meson machine for {route.target_os}/{route.architecture}"
        )
    system, cpu_family, cpu, endian = machine
    path = source_root / "fidb-cross.ini"
    path.write_text(
        "\n".join(
            (
                "[binaries]",
                f"c = {_meson_values(route.compiler)}",
                f"cpp = {_meson_values((_cxx_compiler(route),))}",
                f"ar = {_meson_values(route.archiver)}",
                "",
                "[host_machine]",
                f"system = '{system}'",
                f"cpu_family = '{cpu_family}'",
                f"cpu = '{cpu}'",
                f"endian = '{endian}'",
                "",
                "[properties]",
                "needs_exe_wrapper = true",
                "growing_stack = false",
                "",
                "[built-in options]",
                "default_library = 'static'",
                f"c_args = {_meson_values(compiler_flags)}",
                f"cpp_args = {_meson_values(compiler_flags)}",
                "",
            )
        ),
        encoding="utf-8",
    )


AUTOCONF_ADAPTERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "sqlite-autoconf": (
        ("--disable-shared", "--enable-static"),
        ("libsqlite3.a",),
    ),
    "xz-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-xz",
            "--disable-doc",
            "--disable-nls",
        ),
        ("-C", "src/liblzma", "liblzma.la"),
    ),
    "pcre2-autoconf": (
        ("--disable-shared", "--enable-static"),
        ("libpcre2-8.la",),
    ),
    "gettext-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-java",
            "--disable-csharp",
            "--with-included-libintl",
        ),
        # The directory's recursive `all` target builds its private gnulib
        # archive before libintl; the leaf libintl target alone omits that
        # dependency traversal in gettext 1.0.
        ("-C", "gettext-runtime/intl", "all"),
    ),
    "nghttp2-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-app",
            "--disable-examples",
            "--disable-hpack-tools",
            "--disable-failmalloc",
        ),
        ("-C", "lib", "libnghttp2.la"),
    ),
    "readline-autoconf": (
        ("--disable-shared", "--enable-static"),
        ("libreadline.a", "libhistory.a"),
    ),
    "gmp-autoconf": (
        ("--disable-shared", "--enable-static"),
        # GMP's top-level `all` target first builds host-side generators for
        # tables and headers which are prerequisites of the target library.
        ("all",),
    ),
    "freetype-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--with-zlib=no",
            "--with-bzip2=no",
            "--with-png=no",
            "--with-harfbuzz=no",
            "--with-brotli=no",
        ),
        ("all",),
    ),
    "expat-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--without-xmlwf",
            "--without-examples",
            "--without-tests",
            "--without-docbook",
        ),
        ("-C", "lib", "libexpat.la"),
    ),
    "libunistring-autoconf": (
        ("--disable-shared", "--enable-static", "--disable-rpath"),
        ("-C", "lib", "libunistring.la"),
    ),
    "libtiff-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-tools",
            "--disable-tests",
            "--disable-contrib",
            "--disable-docs",
            "--disable-zlib",
            "--disable-libdeflate",
            "--disable-jpeg",
            "--disable-old-jpeg",
            "--disable-jbig",
            "--disable-lerc",
            "--disable-lzma",
            "--disable-zstd",
            "--disable-webp",
            "--disable-sphinx",
        ),
        ("-C", "libtiff", "libtiff.la"),
    ),
    "libffi-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-docs",
            "--disable-multi-os-directory",
        ),
        ("all",),
    ),
    "libxml2-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--without-python",
            "--without-iconv",
            "--without-icu",
            "--without-zlib",
            "--without-lzma",
            "--without-readline",
            "--without-history",
            "--without-modules",
            "--without-http",
            "--without-docs",
        ),
        ("libxml2.la",),
    ),
    "curl-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-docs",
            "--disable-manual",
            "--disable-threaded-resolver",
            "--without-ssl",
            "--without-zlib",
            "--without-brotli",
            "--without-zstd",
            "--without-libidn2",
            "--without-libpsl",
            "--without-libgsasl",
            "--without-nghttp2",
            "--without-nghttp3",
            "--without-quiche",
            "--without-libssh2",
            "--without-librtmp",
            "--disable-ldap",
            "--disable-ldaps",
            "--without-ldap",
        ),
        ("-C", "lib", "libcurl.la"),
    ),
    "jansson-autoconf": (
        ("--disable-shared", "--enable-static"),
        ("-C", "src", "libjansson.la"),
    ),
    "ncurses-autoconf": (
        (
            "--without-shared",
            "--with-normal",
            "--with-termlib",
            "--without-ada",
            "--without-cxx",
            "--without-cxx-binding",
            "--without-progs",
            "--without-tests",
            "--without-manpages",
            "--disable-widec",
        ),
        ("libs",),
    ),
    "libmicrohttpd-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-doc",
            "--disable-examples",
            "--disable-tools",
            "--disable-curl",
            "--enable-https=no",
        ),
        ("-C", "src/microhttpd", "libmicrohttpd.la"),
    ),
    "hwloc-autoconf": (
        (
            "--disable-shared",
            "--enable-static",
            "--disable-cairo",
            "--disable-libxml2",
            "--disable-io",
            "--disable-pci",
            "--disable-opencl",
            "--disable-cuda",
            "--disable-nvml",
            "--disable-rsmi",
            "--disable-levelzero",
            "--disable-libudev",
            "--enable-plugins=no",
        ),
        ("-C", "hwloc", "libhwloc.la"),
    ),
    "libpcap-autoconf": (
        (
            "--disable-shared",
            "--disable-usb",
            "--disable-bluetooth",
            "--disable-dbus",
            "--disable-rdma",
            "--without-libnl",
            "--without-dag",
            "--without-snf",
            "--without-turbocap",
            "--without-dpdk",
        ),
        ("libpcap.a",),
    ),
}


CMAKE_ADAPTERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "boringssl-cmake": (
        (
            "-DBUILD_TESTING=OFF",
            "-DOPENSSL_NO_ASM=1",
        ),
        ("crypto", "ssl"),
    ),
    "harfbuzz-cmake": (
        (
            "-DHB_BUILD_UTILS=OFF",
            "-DHB_HAVE_CAIRO=OFF",
            "-DHB_HAVE_FREETYPE=OFF",
            "-DHB_HAVE_GRAPHITE2=OFF",
            "-DHB_HAVE_GLIB=OFF",
            "-DHB_HAVE_ICU=OFF",
            "-DHB_HAVE_GOBJECT=OFF",
            "-DHB_HAVE_INTROSPECTION=OFF",
            "-DCMAKE_DISABLE_FIND_PACKAGE_PNG=ON",
            "-DCMAKE_DISABLE_FIND_PACKAGE_ZLIB=ON",
            "-DHB_BUILD_SUBSET=ON",
            "-DHB_BUILD_RASTER=ON",
            "-DHB_BUILD_VECTOR=ON",
            "-DHB_BUILD_GPU=ON",
            "-DHB_BUILD_GPU_DEMO=OFF",
        ),
        (
            "harfbuzz",
            "harfbuzz-subset",
            "harfbuzz-raster",
            "harfbuzz-vector",
            "harfbuzz-gpu",
        ),
    ),
    "brotli-cmake": (
        ("-DBROTLI_BUILD_TOOLS=OFF", "-DBROTLI_DISABLE_TESTS=ON"),
        ("brotlicommon", "brotlidec", "brotlienc"),
    ),
    "libjpeg-turbo-cmake": (
        (
            "-DENABLE_SHARED=OFF",
            "-DENABLE_STATIC=ON",
            "-DWITH_SIMD=OFF",
            "-DWITH_TOOLS=OFF",
            "-DWITH_TESTS=OFF",
            "-DWITH_TURBOJPEG=ON",
            "-DWITH_SYSTEM_ZLIB=OFF",
            "-DWITH_SYSTEM_SPNG=OFF",
        ),
        ("jpeg-static", "turbojpeg-static"),
    ),
    "libpng-cmake": (
        (
            "-DPNG_SHARED=OFF",
            "-DPNG_STATIC=ON",
            "-DPNG_TESTS=OFF",
            "-DPNG_TOOLS=OFF",
            "-DPNG_EXECUTABLES=OFF",
            "-DCMAKE_STATIC_LIBRARY_PREFIX=lib",
        ),
        ("png_static",),
    ),
    "libuv-cmake": (
        (
            "-DLIBUV_BUILD_SHARED=OFF",
            "-DLIBUV_BUILD_TESTS=OFF",
            "-DLIBUV_BUILD_BENCH=OFF",
            "-DBUILD_TESTING=OFF",
        ),
        ("uv_a",),
    ),
    "openjpeg-cmake": (
        (
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_STATIC_LIBS=ON",
            "-DBUILD_CODEC=OFF",
            "-DBUILD_JPIP=OFF",
            "-DBUILD_VIEWER=OFF",
            "-DBUILD_JAVA=OFF",
            "-DBUILD_TESTING=OFF",
            "-DBUILD_DOC=OFF",
        ),
        ("openjp2",),
    ),
    "opus-cmake": (
        (
            "-DOPUS_BUILD_SHARED_LIBRARY=OFF",
            "-DOPUS_BUILD_TESTING=OFF",
            "-DOPUS_BUILD_PROGRAMS=OFF",
            "-DOPUS_STACK_PROTECTOR=OFF",
        ),
        ("opus",),
    ),
    "scotch-cmake": (
        (
            "-DBUILD_FORTRAN=OFF",
            "-DTHREADS=OFF",
            "-DBUILD_PTSCOTCH=OFF",
            "-DBUILD_LIBESMUMPS=OFF",
            "-DBUILD_LIBSCOTCHMETIS=OFF",
            "-DUSE_ZLIB=OFF",
            "-DUSE_LZMA=OFF",
            "-DUSE_BZ2=OFF",
            "-DENABLE_TESTS=OFF",
        ),
        ("scotch",),
    ),
    "opencl-loader-cmake": (
        (
            "-DOPENCL_ICD_LOADER_BUILD_SHARED_LIBS=OFF",
            "-DENABLE_OPENCL_LAYERS=OFF",
            "-DENABLE_OPENCL_LAYERINFO=OFF",
            # Static-library try-compiles cannot prove these functions link.
            # Force the portable getenv fallback for cross targets.
            "-DHAVE_SECURE_GETENV=OFF",
            "-DHAVE___SECURE_GETENV=OFF",
        ),
        ("OpenCL",),
    ),
    "protobuf-cmake": (
        (
            "-Dprotobuf_BUILD_SHARED_LIBS=OFF",
            "-Dprotobuf_BUILD_TESTS=OFF",
            "-Dprotobuf_BUILD_CONFORMANCE=OFF",
            "-Dprotobuf_BUILD_EXAMPLES=OFF",
            "-Dprotobuf_BUILD_PROTOC_BINARIES=OFF",
            "-Dprotobuf_BUILD_LIBPROTOBUF=ON",
            "-Dprotobuf_BUILD_LIBPROTOC=OFF",
            "-Dprotobuf_BUILD_LIBUPB=OFF",
            # Do not let CMake discover an unpinned host zlib while crossing.
            "-Dprotobuf_WITH_ZLIB=OFF",
            "-Dprotobuf_FORCE_FETCH_DEPENDENCIES=ON",
            "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
        ),
        ("libprotobuf",),
    ),
    "mbedtls-cmake": (
        (
            "-DENABLE_PROGRAMS=OFF",
            "-DENABLE_TESTING=OFF",
            "-DUSE_STATIC_MBEDTLS_LIBRARY=ON",
            "-DUSE_SHARED_MBEDTLS_LIBRARY=OFF",
            "-DMBEDTLS_FATAL_WARNINGS=OFF",
            "-DGEN_FILES=OFF",
        ),
        ("tfpsacrypto", "mbedx509", "mbedtls"),
    ),
    "wolfssl-cmake": (
        (
            "-DWOLFSSL_REPRODUCIBLE_BUILD=yes",
            "-DWOLFSSL_INSTALL=no",
            "-DWOLFSSL_ASM=no",
            "-DWOLFSSL_EXAMPLES=no",
            "-DWOLFSSL_CRYPT_TESTS=no",
            # Windows has gmtime_s, not the POSIX gmtime_r contract. A static
            # try-compile otherwise reports a false positive while crossing.
            "-DHAVE_GMTIME_R=OFF",
        ),
        ("wolfssl",),
    ),
}


def _cmake_target_options(route: Route) -> tuple[str, ...]:
    systems = {"linux": "Linux", "windows": "Windows", "android": "Android"}
    system = systems.get(route.target_os)
    if system is None:
        raise AdapterError(
            f"no reviewed CMake target for {route.target_os}/{route.architecture}"
        )
    options = [f"-DCMAKE_SYSTEM_NAME={system}"]
    if route.target_os == "android":
        abi = {
            "aarch64": "arm64-v8a",
            "arm": "armeabi-v7a",
            "x86_64": "x86_64",
            "i686": "x86",
        }.get(route.architecture)
        if abi is None:
            raise AdapterError(
                f"no reviewed Android CMake ABI for {route.architecture}"
            )
        options.extend(
            (
                f"-DCMAKE_ANDROID_NDK={_android_ndk_root(route)}",
                f"-DCMAKE_ANDROID_ARCH_ABI={abi}",
                "-DCMAKE_SYSTEM_VERSION=21",
            )
        )
    else:
        options.append(f"-DCMAKE_SYSTEM_PROCESSOR={route.architecture}")
    return tuple(options)


def build_commands(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
    jobs: int,
    source_root: Path | None = None,
) -> tuple[tuple[str, ...], ...]:
    compiler = tool_text(route.compiler)
    archiver = tool_text(route.archiver)
    ranlib = tool_text(route.ranlib)
    flags = " ".join(compiler_flags)
    if build_system == "openssl-configure":
        if route.target_os == "windows" and route.architecture == "x86_64":
            target = "mingw64"
        elif route.target_os == "linux":
            target = {
                "x86_64": "linux-x86_64",
                "arm": "linux-armv4",
                "aarch64": "linux-aarch64",
                "mips": "linux-mips32",
                "mipsel": "linux-mips32",
                "powerpc": "linux-ppc",
                "sh4": "linux-generic32",
                "m68k": "linux-generic32",
            }.get(route.architecture, "")
        elif route.target_os == "android":
            target = {
                "aarch64": "android-arm64",
                "arm": "android-arm",
                "i686": "android-x86",
                "x86_64": "android-x86_64",
            }.get(route.architecture, "")
        else:
            target = ""
        if not target:
            raise AdapterError(
                f"no OpenSSL Configure target for {route.target_os}/{route.architecture}"
            )
        configure = [
            "perl",
            "Configure",
            target,
            "no-shared",
            "no-tests",
            "no-docs",
            "no-module",
        ]
        if route.target_os == "android":
            configure.append("-D__ANDROID_API__=21")
        return (
            tuple(configure),
            ("make", f"-j{jobs}", "build_libs"),
        )
    if build_system == "autoconf":
        return (
            ("sh", "configure", "--static"),
            (
                "make",
                f"-j{jobs}",
                "libz.a",
                f"AR={archiver}",
                "ARFLAGS=rc",
                f"RANLIB={ranlib}",
            ),
        )
    if build_system == "make":
        return (
            (
                "make",
                f"-j{jobs}",
                "libbz2.a",
                f"CC={compiler}",
                f"CFLAGS=-Wall -Winline -D_FILE_OFFSET_BITS=64 {flags}",
                f"AR={archiver}",
                f"RANLIB={ranlib}",
            ),
        )
    if build_system == "krb5-autoconf":
        return (
            ("cmake", "-E", "make_directory", "fidb-build"),
            (
                "cmake",
                "-E",
                "chdir",
                "fidb-build",
                "sh",
                "../src/configure",
                f"--host={_configure_host(route)}",
                "--disable-shared",
                "--enable-static",
                "--without-libedit",
                "--without-readline",
                "--without-system-verto",
                "--without-ldap",
                "--without-hesiod",
            ),
            ("make", f"-j{jobs}", "-C", "fidb-build/util", "all"),
            ("make", f"-j{jobs}", "-C", "fidb-build/include", "all"),
            ("make", f"-j{jobs}", "-C", "fidb-build/lib", "all"),
            # The top-level library directory contains a convenience symlink
            # to the real archive in lib/krb5. Keep only the real archive so
            # discovery has one unambiguous, inspectable input.
            ("cmake", "-E", "remove", "fidb-build/lib/libkrb5.a"),
        )
    if build_system == "e2fsprogs-comerr-autoconf":
        return (
            (
                "sh",
                "configure",
                f"--host={_configure_host(route)}",
                "--disable-elf-shlibs",
                "--disable-bsd-shlibs",
                "--enable-libuuid",
                "--enable-libblkid",
                "--disable-debugfs",
                "--disable-imager",
                "--disable-resizer",
                "--disable-defrag",
                "--disable-fsck",
                "--disable-uuidd",
                "--disable-fuse2fs",
            ),
            ("make", f"-j{jobs}", "-C", "lib/et", "libcom_err.a"),
            # e2fsprogs hard-links the same archive into lib/. Archive
            # discovery intentionally rejects duplicate paths, so retain the
            # canonical lib/et output only.
            ("cmake", "-E", "remove", "lib/libcom_err.a"),
        )
    if build_system == "libedit-autoconf":
        if source_root is None or not source_root.is_absolute():
            raise AdapterError("libedit adapter requires an absolute source root")
        dependency_source = source_root / "fidb-inputs/ncurses-6.6"
        dependency_build = source_root / "fidb-deps/ncurses-build"
        dependency_install = source_root / "fidb-deps/ncurses-install"
        return (
            ("cmake", "-E", "make_directory", str(dependency_build)),
            (
                "cmake",
                "-E",
                "chdir",
                str(dependency_build),
                "sh",
                str(dependency_source / "configure"),
                f"--host={_configure_host(route)}",
                f"--prefix={dependency_install}",
                "--without-shared",
                "--with-normal",
                "--with-termlib",
                "--without-ada",
                "--without-cxx",
                "--without-cxx-binding",
                "--without-progs",
                "--without-tests",
                "--without-manpages",
                "--disable-widec",
            ),
            ("make", f"-j{jobs}", "-C", str(dependency_build), "libs"),
            (
                "make",
                "-C",
                str(dependency_build),
                "install.includes",
                "install.libs",
            ),
            (
                "env",
                (
                    f"CPPFLAGS=-I{dependency_install}/include "
                    f"-I{dependency_install}/include/ncurses"
                ),
                f"LDFLAGS=-L{dependency_install}/lib",
                "sh",
                "configure",
                f"--host={_configure_host(route)}",
                "--disable-shared",
                "--enable-static",
                "--disable-examples",
            ),
            (
                "make",
                "-C",
                "src",
                "vi.h",
                "emacs.h",
                "common.h",
                "fcns.h",
                "help.h",
                "func.h",
            ),
            ("make", f"-j{jobs}", "-C", "src", "libedit.la"),
        )
    if build_system == "libssh2-autoconf":
        if source_root is None or not source_root.is_absolute():
            raise AdapterError("libssh2 adapter requires an absolute source root")
        dependency_source = source_root / "fidb-inputs/wolfssl-5.9.2-1"
        dependency_build = source_root / "fidb-deps/wolfssl-build"
        dependency_install = source_root / "fidb-deps/wolfssl-install"
        dependency_configure = (
            "cmake",
            "-S",
            str(dependency_source),
            "-B",
            str(dependency_build),
            "-G",
            "Ninja",
            "-DWOLFSSL_REPRODUCIBLE_BUILD=yes",
            "-DWOLFSSL_INSTALL=yes",
            "-DWOLFSSL_OPENSSLEXTRA=yes",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DWOLFSSL_ASM=no",
            "-DWOLFSSL_EXAMPLES=no",
            "-DWOLFSSL_CRYPT_TESTS=no",
            "-DHAVE_GMTIME_R=OFF",
            f"-DCMAKE_INSTALL_PREFIX={dependency_install}",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
            f"-DCMAKE_C_COMPILER={compiler}",
            f"-DCMAKE_CXX_COMPILER={_cxx_compiler(route)}",
            f"-DCMAKE_AR={archiver}",
            f"-DCMAKE_RANLIB={ranlib}",
            f"-DCMAKE_C_FLAGS={flags}",
            f"-DCMAKE_CXX_FLAGS={flags}",
            *_cmake_target_options(route),
        )
        return (
            dependency_configure,
            (
                "cmake",
                "--build",
                str(dependency_build),
                "--parallel",
                str(jobs),
                "--target",
                "wolfssl",
            ),
            ("cmake", "--install", str(dependency_build)),
            (
                "sh",
                "./configure",
                f"--host={_configure_host(route)}",
                "--disable-shared",
                "--enable-static",
                "--disable-examples-build",
                "--disable-docker-tests",
                "--disable-sshd-tests",
                "--with-crypto=wolfssl",
                f"--with-libwolfssl-prefix={dependency_install}",
                "--without-libz",
            ),
            ("make", f"-j{jobs}", "-C", "src", "libssh2.la"),
        )
    if build_system == "musl-cross":
        if route.target_os != "linux":
            raise AdapterError("musl source builds are reviewed only for Linux")
        return (
            (
                "sh",
                "./configure",
                f"--target={_configure_host(route)}",
                "--disable-shared",
            ),
            ("make", f"-j{jobs}", "lib/libc.a"),
        )
    if build_system == "perl-native":
        if route.target_os != "linux" or route.architecture != "x86_64":
            raise AdapterError(
                "libperl is reviewed only for native-compatible Linux x86-64"
            )
        return (
            (
                "sh",
                "Configure",
                "-des",
                "-Dprefix=/usr",
                f"-Dcc={compiler}",
                f"-Dar={archiver}",
                f"-Dranlib={ranlib}",
                f"-Doptimize={flags}",
                f"-Dccflags={flags}",
                "-Dldflags=",
                "-Dlocincpth=/nonexistent",
                "-Dloclibpth=/nonexistent",
                "-Dlibs=-lpthread -ldl -lm -lutil -lc",
                "-Duseshrplib=false",
                "-Duseithreads=undef",
                "-Dusemultiplicity=undef",
            ),
            ("make", f"-j{jobs}", "libperl.a"),
        )
    if build_system in AUTOCONF_ADAPTERS:
        configure_options, make_targets = AUTOCONF_ADAPTERS[build_system]
        # curl 8.22's Autoconf probe incorrectly enables IPv6 with the oldest
        # reviewed llvm-mingw route even though its getaddrinfo declaration was
        # not detected.  The resulting curl_setup.h deliberately aborts every
        # compilation.  Keep the workaround bound to that exact compiler
        # authority; newer llvm-mingw routes pass the probe and retain IPv6.
        if (
            build_system == "curl-autoconf"
            and route.id == "windows-x86-64-llvm-mingw-clang-15"
        ):
            configure_options = (*configure_options, "--disable-ipv6")
        commands = [
            (
                "sh",
                "configure",
                f"--host={_configure_host(route)}",
                *configure_options,
            ),
        ]
        if build_system == "readline-autoconf" and route.target_os == "windows":
            # Readline 8.3 declares an otherwise-unused POSIX winsize tag in
            # two MinGW objects without defining it. Map that opaque tag to a
            # real Windows console struct for only those objects; their Win32
            # branches do not dereference it.
            commands.append(
                (
                    "make",
                    "terminal.o",
                    "rltty.o",
                    (
                        f"CFLAGS={flags} -include windows.h "
                        "-Dwinsize=_CONSOLE_SCREEN_BUFFER_INFO"
                    ),
                )
            )
        commands.append(("make", f"-j{jobs}", *make_targets))
        return tuple(commands)
    if build_system in CMAKE_ADAPTERS:
        project_options, targets = CMAKE_ADAPTERS[build_system]
        source = "src" if build_system == "boringssl-cmake" else "."
        if build_system == "opencl-loader-cmake":
            if source_root is None or not source_root.is_absolute():
                raise AdapterError(
                    "OpenCL loader adapter requires an absolute source root"
                )
            project_options = (
                *project_options,
                "-DOPENCL_ICD_LOADER_HEADERS_DIR="
                f"{source_root}/fidb-inputs/opencl-headers-2026.05.29",
            )
        if build_system == "protobuf-cmake":
            if source_root is None or not source_root.is_absolute():
                raise AdapterError("Protobuf adapter requires an absolute source root")
            project_options = (
                *project_options,
                "-DFETCHCONTENT_SOURCE_DIR_ABSL="
                f"{source_root}/fidb-inputs/abseil-cpp-20250512.1",
            )
        if build_system == "boringssl-cmake":
            if source_root is None or not source_root.is_absolute():
                raise AdapterError("BoringSSL adapter requires an absolute source root")
            project_options = (
                *project_options,
                f"-DGO_EXECUTABLE={source_root}/fidb-boringssl-go",
            )
        configure = (
            "cmake",
            "-S",
            source,
            "-B",
            "fidb-build",
            "-G",
            "Ninja",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
            f"-DCMAKE_C_COMPILER={compiler}",
            f"-DCMAKE_CXX_COMPILER={_cxx_compiler(route)}",
            f"-DCMAKE_AR={archiver}",
            f"-DCMAKE_RANLIB={ranlib}",
            f"-DCMAKE_C_FLAGS={flags}",
            f"-DCMAKE_CXX_FLAGS={flags}",
            *_cmake_target_options(route),
            *project_options,
        )
        build = (
            "cmake",
            "--build",
            "fidb-build",
            "--parallel",
            str(jobs),
            "--target",
            *targets,
        )
        if build_system != "libpng-cmake":
            if build_system == "opencl-loader-cmake" and route.target_os == "windows":
                return (
                    configure,
                    build,
                    (
                        "cmake",
                        "-E",
                        "copy",
                        "fidb-build/OpenCL.a",
                        "fidb-build/libOpenCL.a",
                    ),
                )
            return (configure, build)
        if source_root is None or not source_root.is_absolute():
            raise AdapterError("libpng adapter requires an absolute source root")
        zlib_source = source_root / "fidb-inputs/zlib-1.3.1"
        zlib_build = source_root / "fidb-deps/zlib-build"
        zlib_install = source_root / "fidb-deps/zlib-install"
        dependency_configure = (
            "cmake",
            "-S",
            str(zlib_source),
            "-B",
            str(zlib_build),
            "-G",
            "Ninja",
            "-DZLIB_BUILD_EXAMPLES=OFF",
            "-DSKIP_INSTALL_FILES=ON",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
            f"-DCMAKE_INSTALL_PREFIX={zlib_install}",
            f"-DCMAKE_C_COMPILER={compiler}",
            f"-DCMAKE_AR={archiver}",
            f"-DCMAKE_RANLIB={ranlib}",
            f"-DCMAKE_C_FLAGS={flags}",
            *_cmake_target_options(route),
        )
        return (
            dependency_configure,
            (
                "cmake",
                "--build",
                str(zlib_build),
                "--parallel",
                str(jobs),
            ),
            ("cmake", "--install", str(zlib_build)),
            (*configure, f"-DZLIB_ROOT={zlib_install}"),
            build,
        )
    if build_system == "lz4-make":
        platform = ("TARGET_OS=Windows_NT",) if route.target_os == "windows" else ()
        return (
            (
                "make",
                f"-j{jobs}",
                "liblz4.a",
                f"CC={compiler}",
                f"CFLAGS={flags}",
                f"AR={archiver}",
                *platform,
            ),
        )
    if build_system == "zstd-make":
        platform = ("TARGET_SYSTEM=Windows_NT",) if route.target_os == "windows" else ()
        return (
            (
                "make",
                f"-j{jobs}",
                "-C",
                "lib",
                "BUILD_DIR=obj/fidb",
                "obj/fidb/static/libzstd.a",
                f"CC={compiler}",
                f"CFLAGS={flags}",
                f"AR={archiver}",
                *platform,
            ),
        )
    if build_system == "glib-meson":
        if source_root is None or not source_root.is_absolute():
            raise AdapterError("GLib adapter requires an absolute source root")
        return (
            (
                "meson",
                "setup",
                "fidb-build",
                "--cross-file",
                str(source_root / "fidb-cross.ini"),
                "--wrap-mode=forcefallback",
                "--default-library=static",
                "--buildtype=plain",
                "-Db_lto=false",
                "-Dtests=false",
                "-Dinstalled_tests=false",
                "-Ddocumentation=false",
                "-Dintrospection=disabled",
                "-Dman-pages=disabled",
                "-Dnls=disabled",
                "-Dlibmount=disabled",
                "-Dselinux=disabled",
                "-Dlibelf=disabled",
                "-Dxattr=false",
                "-Ddtrace=disabled",
                "-Dsystemtap=disabled",
                "-Dsysprof=disabled",
                "-Dglib_debug=disabled",
            ),
            (
                "meson",
                "compile",
                "-C",
                "fidb-build",
                "-j",
                str(jobs),
                "glib-2.0",
                "gmodule-2.0",
                "gobject-2.0",
                "gio-2.0",
            ),
        )
    raise AdapterError(
        f"detected build system {build_system!r} has no implemented adapter"
    )


def build_environment(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
) -> dict[str, str]:
    if (
        build_system
        not in {
            "autoconf",
            "openssl-configure",
            "glib-meson",
        }
        and not build_system.endswith("-autoconf")
        and build_system not in CMAKE_ADAPTERS
        and build_system not in {"musl-cross", "perl-native"}
    ):
        return {}
    environment = {
        "CC": tool_text(route.compiler),
        "AR": tool_text(route.archiver),
        "RANLIB": tool_text(route.ranlib),
        "CFLAGS": " ".join(compiler_flags),
    }
    if build_system in CMAKE_ADAPTERS:
        environment["CXX"] = _cxx_compiler(route)
        environment["CXXFLAGS"] = " ".join(compiler_flags)
    if build_system == "glib-meson":
        environment["CXX"] = _cxx_compiler(route)
        environment["CXXFLAGS"] = " ".join(compiler_flags)
        environment["CC_FOR_BUILD"] = "/usr/bin/cc"
        environment["CXX_FOR_BUILD"] = "/usr/bin/c++"
    if build_system == "gmp-autoconf":
        # GMP builds target-independent table/header generators during a cross
        # build. Its fallback can incorrectly reuse CC and then attempt to run
        # a Windows target executable on the Linux build host.
        environment["CC_FOR_BUILD"] = "/usr/bin/cc"
    if build_system in {"krb5-autoconf", "e2fsprogs-comerr-autoconf"}:
        environment["BUILD_CC"] = "/usr/bin/cc"
    if build_system == "gettext-autoconf":
        environment["CXX"] = _cxx_compiler(route)
    if route.target_os == "android":
        ndk_root = _android_ndk_root(route)
        ndk_bin = ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        environment["ANDROID_NDK_ROOT"] = str(ndk_root)
        environment["PATH"] = f"{ndk_bin}:/usr/bin:/bin"
        if build_system == "libedit-autoconf":
            # Android uses a 32-bit Unicode wchar_t but does not advertise the
            # optional ISO 10646 conformance macro expected by libedit. Its
            # BSD-derived vis implementation also expects NBBY, which Android
            # deliberately does not expose through sys/param.h.
            environment["CFLAGS"] = (
                f'{environment["CFLAGS"]} -D__STDC_ISO_10646__=201103L -DNBBY=8'
            ).strip()
    elif route.target_os == "windows":
        toolchain_bin = Path(route.compiler[0]).parent
        environment["PATH"] = f"{toolchain_bin}:/usr/bin:/bin"
        environment["WINDRES"] = str(toolchain_bin / "x86_64-w64-mingw32-windres")
    return environment


def linked_output_command(
    *,
    route: Route,
    treatment: Treatment,
    archives: tuple[Path, ...],
    output: Path,
) -> tuple[str, ...]:
    """Return the fixed route adapter for materialising a linked library image."""
    if route.target_os not in {"linux", "android"}:
        raise AdapterError(
            f"no linked-output adapter in the ELF PoC for {route.target_os!r}"
        )
    command = [*route.compiler, *treatment.flags_for(route)]
    command.extend(("-shared", "-nostdlib", "-Wl,--whole-archive"))
    command.extend(str(archive) for archive in archives)
    command.append("-Wl,--no-whole-archive")
    if treatment.factor == "linker_transformation":
        command.append("-Wl,--gc-sections")
    command.extend(("-o", str(output)))
    return tuple(command)


def find_static_archives(
    source_root: Path, expected_names: tuple[str, ...]
) -> tuple[Path, ...]:
    archives = []
    for name in expected_names:
        matches = sorted(path for path in source_root.rglob(name) if path.is_file())
        if len(matches) != 1:
            raise AdapterError(
                f"expected exactly one {name!r} under {source_root}, found {matches}"
            )
        archives.append(matches[0])
    return tuple(archives)


def copy_pristine_source(source_root: Path, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source_root, destination)
    return destination
