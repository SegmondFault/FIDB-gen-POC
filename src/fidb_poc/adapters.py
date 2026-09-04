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
}


def build_commands(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
    jobs: int,
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
    if build_system in AUTOCONF_ADAPTERS:
        configure_options, make_targets = AUTOCONF_ADAPTERS[build_system]
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
        platform = (
            ("TARGET_SYSTEM=Windows_NT",) if route.target_os == "windows" else ()
        )
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
    raise AdapterError(
        f"detected build system {build_system!r} has no implemented adapter"
    )


def build_environment(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
) -> dict[str, str]:
    if build_system not in {
        "autoconf",
        "openssl-configure",
    } and not build_system.endswith("-autoconf"):
        return {}
    environment = {
        "CC": tool_text(route.compiler),
        "AR": tool_text(route.archiver),
        "RANLIB": tool_text(route.ranlib),
        "CFLAGS": " ".join(compiler_flags),
    }
    if build_system == "gmp-autoconf":
        # GMP builds target-independent table/header generators during a cross
        # build. Its fallback can incorrectly reuse CC and then attempt to run
        # a Windows target executable on the Linux build host.
        environment["CC_FOR_BUILD"] = "/usr/bin/cc"
    if build_system == "gettext-autoconf":
        environment["CXX"] = _cxx_compiler(route)
    if route.target_os == "android":
        ndk_root = _android_ndk_root(route)
        ndk_bin = ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        environment["ANDROID_NDK_ROOT"] = str(ndk_root)
        environment["PATH"] = f"{ndk_bin}:/usr/bin:/bin"
    elif route.target_os == "windows":
        toolchain_bin = Path(route.compiler[0]).parent
        environment["PATH"] = f"{toolchain_bin}:/usr/bin:/bin"
        environment["WINDRES"] = str(
            toolchain_bin / "x86_64-w64-mingw32-windres"
        )
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
