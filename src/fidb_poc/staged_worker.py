"""Machine-facing worker protocol for the experimental staged backend."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys

from .staged_backend import execute_analysis_job, execute_build_job

SERVICE_FRAME = "FIDB_RESULT\t"


def _emit(document: dict[str, object], *, framed: bool = False) -> None:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    print(f"{SERVICE_FRAME if framed else ''}{payload}", flush=True)


def _build(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="fidb-staged-worker build")
    parser.add_argument("--job", required=True)
    parser.add_argument("--build-jobs", type=int, default=4)
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = execute_build_job(
            arguments.job,
            verbose=arguments.verbose,
            build_jobs_per_cell=arguments.build_jobs,
        )
    except Exception as error:
        _emit(
            {
                "stage": "build",
                "job_path": arguments.job,
                "pipeline_error": f"{type(error).__name__}: {error}",
            }
        )
        return 1
    _emit(result)
    return 0 if not result["pipeline_error"] else 1


def _service(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="fidb-staged-worker service")
    parser.add_argument("--java-options", default="")
    parser.add_argument("--verbose", action="store_true")
    arguments = parser.parse_args(argv)
    for line in sys.stdin:
        request: object = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or set(request) != {"job_path"}:
                raise ValueError("service request must contain only job_path")
            # stdout is the machine protocol.  Ghidra and build adapters may
            # write informational text, so keep it on the diagnostic stream.
            with contextlib.redirect_stdout(sys.stderr):
                result = execute_analysis_job(
                    str(request["job_path"]),
                    verbose=arguments.verbose,
                    java_options=arguments.java_options,
                )
        except Exception as error:
            result = {
                "stage": "analysis",
                "job_path": (
                    str(request.get("job_path", ""))
                    if isinstance(request, dict)
                    else ""
                ),
                "pipeline_error": f"{type(error).__name__}: {error}",
            }
        _emit(result, framed=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if not tokens:
        print("error: expected build or service", file=sys.stderr)
        return 2
    if tokens[0] == "build":
        return _build(tokens[1:])
    if tokens[0] == "service":
        return _service(tokens[1:])
    print(f"error: unknown staged worker command: {tokens[0]}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
