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
        if present:
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
    raise AdapterError(
        f"detected build system {build_system!r} has no implemented adapter"
    )


def build_environment(
    build_system: str,
    *,
    route: Route,
    compiler_flags: tuple[str, ...],
) -> dict[str, str]:
    if build_system != "autoconf":
        return {}
    return {
        "CC": tool_text(route.compiler),
        "AR": tool_text(route.archiver),
        "RANLIB": tool_text(route.ranlib),
        "CFLAGS": " ".join(compiler_flags),
    }


def linked_output_command(
    *,
    route: Route,
    treatment: Treatment,
    archives: tuple[Path, ...],
    output: Path,
) -> tuple[str, ...]:
    """Return the fixed route adapter for materialising a linked library image."""
    if route.target_os != "linux":
        raise AdapterError(
            f"no linked-output adapter in the Linux PoC for {route.target_os!r}"
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
