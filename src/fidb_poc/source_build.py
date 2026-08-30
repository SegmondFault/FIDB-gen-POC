"""Execute reviewed source-build adapters through QEMU or local Linux.

Executor selection changes only where the fixed adapter invocation runs. The
source archive, cross-toolchain, adapter name, flags, target ABI and output
path remain resolved cell inputs; neither recipes nor callers can supply a
raw command.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys
import time
import zipfile

from .timing import utc_now

log = logging.getLogger(__name__)

EXECUTORS = ("qemu", "local")
BUILD_ADAPTERS = ("uclibc_defconfig", "plain_make", "mirai_bot_gcc")
_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"


@dataclass(frozen=True)
class AdapterInputs:
    """The reviewed, executor-independent inputs to one build adapter."""

    build_adapter: str
    arch: str
    cross_bin_prefix: str
    output_relpath: str
    jobs: int = 4

    def __post_init__(self) -> None:
        if self.build_adapter not in BUILD_ADAPTERS:
            raise ValueError(f"unsupported build adapter: {self.build_adapter}")
        if (
            self.build_adapter in ("uclibc_defconfig", "mirai_bot_gcc")
            and not self.arch
        ):
            raise ValueError(f"arch is required for build adapter {self.build_adapter}")
        if self.jobs < 1:
            raise ValueError("jobs must be at least 1")


@dataclass(frozen=True)
class AdapterInvocation:
    cwd: Path
    command: tuple[str, ...]


def executor_for(cell: dict[str, object]) -> str:
    executor = str(cell.get("executor", "qemu"))
    if executor not in EXECUTORS:
        raise ValueError(f"unsupported source-build executor: {executor}")
    return executor


def adapter_inputs(cell: dict[str, object], default_adapter: str) -> AdapterInputs:
    return AdapterInputs(
        build_adapter=str(cell.get("build_adapter", default_adapter)),
        arch=str(cell.get("arch", "")),
        cross_bin_prefix=str(cell["cross_bin_prefix"]),
        output_relpath=str(cell["library_path"]),
    )


def adapter_invocation(
    inputs: AdapterInputs, source_root: Path, toolchain_root: Path
) -> AdapterInvocation:
    cross_prefix = str(toolchain_root / inputs.cross_bin_prefix)
    if inputs.build_adapter == "uclibc_defconfig":
        return AdapterInvocation(
            cwd=source_root,
            command=(
                "make",
                f"ARCH={inputs.arch}",
                f"CROSS={cross_prefix}",
                f"-j{inputs.jobs}",
            ),
        )
    if inputs.build_adapter == "plain_make":
        return AdapterInvocation(
            cwd=source_root,
            command=("make", f"CC={cross_prefix}gcc", f"-j{inputs.jobs}"),
        )

    output = Path(inputs.output_relpath)
    return AdapterInvocation(
        cwd=source_root / output.parent,
        command=(
            f"{cross_prefix}gcc",
            "-std=c99",
            "bot/*.c",
            "-O3",
            "-fomit-frame-pointer",
            "-fdata-sections",
            "-ffunction-sections",
            "-Wl,--gc-sections",
            "-o",
            output.name,
            f'-DMIRAI_BOT_ARCH="{inputs.arch}"',
            "-DMIRAI_TELNET",
            "-static",
        ),
    )


def shell_adapter_command(
    inputs: AdapterInputs, source_root: Path, toolchain_root: Path
) -> str:
    """Render the shared invocation for the QEMU guest's interactive shell."""
    invocation = adapter_invocation(inputs, source_root, toolchain_root)
    command = list(invocation.command)
    if inputs.build_adapter == "mirai_bot_gcc":
        # The fork's reviewed command uses a source glob. Quote every other
        # argument while leaving that one fixed adapter-owned glob expandable.
        rendered = " ".join(
            argument if argument == "bot/*.c" else shlex.quote(argument)
            for argument in command
        )
    else:
        rendered = shlex.join(command)
    return f"cd {shlex.quote(str(invocation.cwd))} && {rendered}"


def run_local_source_build(
    inputs: AdapterInputs,
    source_root: Path,
    toolchain_root: Path,
    out_dir: Path,
) -> Path:
    """Run one fixed cross-build adapter directly in the invoking Linux environment."""
    invocation = adapter_invocation(inputs, source_root, toolchain_root)
    log.info(
        "local build: cwd=%s command=%s", invocation.cwd, shlex.join(invocation.command)
    )
    command = list(invocation.command)
    if inputs.build_adapter == "mirai_bot_gcc":
        sources = [str(path) for path in sorted(invocation.cwd.glob("bot/*.c"))]
        if not sources:
            raise ValueError(
                f"{invocation.cwd}: mirai_bot_gcc found no bot/*.c sources"
            )
        command[command.index("bot/*.c") : command.index("bot/*.c") + 1] = sources
    out_dir.mkdir(parents=True, exist_ok=True)
    timing_log = out_dir / "reviewed-build-command.log"
    started_at = utc_now()
    started_ns = time.monotonic_ns()
    outcome = "failed"
    returncode: int | None = None
    try:
        result = subprocess.run(command, cwd=invocation.cwd, check=True, timeout=2400)
        returncode = result.returncode
        outcome = "completed"
    except subprocess.TimeoutExpired:
        outcome = "timeout"
        raise
    except subprocess.CalledProcessError as error:
        returncode = error.returncode
        raise
    finally:
        timing_log.write_text(
            "\n".join(
                (
                    f"$ {shlex.join(command)}",
                    f"cwd={invocation.cwd}",
                    f"started_at_utc={started_at}",
                    f"finished_at_utc={utc_now()}",
                    f"duration_ns={max(0, time.monotonic_ns() - started_ns)}",
                    f"outcome={outcome}",
                    f"returncode={returncode if returncode is not None else 'unavailable'}",
                    "",
                )
            ),
            encoding="utf-8",
        )
    built = source_root / inputs.output_relpath
    if not built.is_file():
        raise ValueError(f"local source build did not produce {inputs.output_relpath}")
    destination = out_dir / built.name
    shutil.copy2(built, destination)
    return destination


def extract_zip_source(archive: Path, destination: Path) -> str:
    """Extract a pinned ZIP for the explicitly opted-in local executor."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        names = [entry.filename for entry in source.infolist() if entry.filename]
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe zip archive path: {name}")
        top_level = {PurePosixPath(name).parts[0] for name in names}
        if len(top_level) != 1:
            raise ValueError(
                f"expected a single top-level directory in {archive}, got {top_level}"
            )
        source.extractall(destination)
    return next(iter(top_level))


def run_qemu_source_build(
    inputs: AdapterInputs,
    work: Path,
    iso: Path,
    toolchain_dir_name: str,
    *,
    src_dir_name: str | None = None,
    payload_archive: str | None = None,
    payload_kind: str | None = None,
) -> None:
    """Run the existing QEMU executor with the same reviewed adapter inputs."""
    if bool(src_dir_name) == bool(payload_archive):
        raise ValueError("exactly one source directory or payload archive is required")
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(work / "scratch.qcow2"), "3G"],
        check=True,
    )
    payload_args = (
        ["--src-dir", str(src_dir_name)]
        if src_dir_name
        else [
            "--payload-archive",
            str(payload_archive),
            "--payload-kind",
            str(payload_kind),
        ]
    )
    subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS_DIR / "drive_source_vm_build.py"),
            "--work",
            str(work),
            "--iso",
            str(iso),
            *payload_args,
            "--toolchain-dir",
            toolchain_dir_name,
            "--build-adapter",
            inputs.build_adapter,
            "--arch",
            inputs.arch,
            "--cross-bin-prefix",
            inputs.cross_bin_prefix,
            "--output-relpath",
            inputs.output_relpath,
            "--jobs",
            str(inputs.jobs),
        ],
        check=True,
        timeout=3000,
    )
