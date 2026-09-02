"""Validated scheduling, admission and notification policy for queue workers."""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Mapping, Sequence
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
NOTIFICATION_EVENTS = (
    "job-failed",
    "job-requeued",
    "queue-drained",
    "resource-blocked",
    "schedule-cutoff",
)


def _only_keys(row: Mapping[str, object], allowed: set[str], context: str) -> None:
    unknown = set(row) - allowed
    if unknown:
        raise ValueError(f"{context} contains unsupported fields: {sorted(unknown)}")


def _nonnegative_number(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{context} must be a non-negative number")
    return float(value)


def _clock(value: object, context: str) -> time:
    if not isinstance(value, str):
        raise ValueError(f"{context} must use HH:MM")
    try:
        parsed = time.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{context} must use HH:MM") from error
    if parsed.second or parsed.microsecond or len(value) != 5:
        raise ValueError(f"{context} must use HH:MM")
    return parsed


def _table(document: Mapping[str, object], name: str) -> Mapping[str, object]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"queue {name} must be a table")
    return value


@dataclass(frozen=True)
class ScheduleState:
    claims_allowed: bool
    reason: str
    window_started_at: str | None
    stop_claiming_at: str | None
    hard_cutoff_at: str | None
    next_window_at: str | None

    def document(self) -> dict[str, object]:
        return {
            "claims_allowed": self.claims_allowed,
            "reason": self.reason,
            "window_started_at": self.window_started_at,
            "stop_claiming_at": self.stop_claiming_at,
            "hard_cutoff_at": self.hard_cutoff_at,
            "next_window_at": self.next_window_at,
        }


@dataclass(frozen=True)
class SchedulePolicy:
    enabled: bool = False
    timezone_name: str = "UTC"
    days: tuple[str, ...] = DAY_NAMES
    start: time = time(0, 0)
    stop_claiming: time = time(23, 58)
    hard_cutoff: time = time(23, 59)

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    def document(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "timezone": self.timezone_name,
            "days": list(self.days),
            "start": self.start.strftime("%H:%M"),
            "stop_claiming": self.stop_claiming.strftime("%H:%M"),
            "hard_cutoff": self.hard_cutoff.strftime("%H:%M"),
        }

    def _boundary(self, start_date: date, clock: time) -> datetime:
        day = start_date
        if clock <= self.start:
            day += timedelta(days=1)
        return datetime.combine(day, clock, self.zone)

    def _window(self, start_date: date) -> tuple[datetime, datetime, datetime]:
        started = datetime.combine(start_date, self.start, self.zone)
        stop = self._boundary(start_date, self.stop_claiming)
        cutoff = self._boundary(start_date, self.hard_cutoff)
        if stop > cutoff:
            raise ValueError("schedule stop_claiming must not be after hard_cutoff")
        return started, stop, cutoff

    def evaluate(self, now: datetime | None = None) -> ScheduleState:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("schedule evaluation requires a timezone-aware datetime")
        local = current.astimezone(self.zone)
        if not self.enabled:
            return ScheduleState(True, "schedule-disabled", None, None, None, None)

        candidate_date = local.date()
        if local.timetz().replace(tzinfo=None) < self.start:
            candidate_date -= timedelta(days=1)
        started, stop, cutoff = self._window(candidate_date)
        day_enabled = DAY_NAMES[candidate_date.weekday()] in self.days
        inside = day_enabled and started <= local < cutoff
        claims_allowed = inside and local < stop

        next_window = None
        for offset in range(0, 9):
            next_date = local.date() + timedelta(days=offset)
            if DAY_NAMES[next_date.weekday()] not in self.days:
                continue
            next_start = datetime.combine(next_date, self.start, self.zone)
            if next_start > local:
                next_window = next_start
                break

        if claims_allowed:
            reason = "inside-claim-window"
        elif inside:
            reason = "claim-window-closed"
        else:
            reason = "outside-schedule-window"
        return ScheduleState(
            claims_allowed,
            reason,
            started.isoformat() if inside else None,
            stop.isoformat() if inside else None,
            cutoff.isoformat() if inside else None,
            next_window.isoformat() if next_window else None,
        )


@dataclass(frozen=True)
class ResourcePolicy:
    min_available_memory_gib: float = 0
    min_free_disk_gib: float = 0
    max_load_per_cpu: float = 0
    max_temperature_c: float = 0

    def document(self) -> dict[str, float]:
        return {
            "min_available_memory_gib": self.min_available_memory_gib,
            "min_free_disk_gib": self.min_free_disk_gib,
            "max_load_per_cpu": self.max_load_per_cpu,
            "max_temperature_c": self.max_temperature_c,
        }


@dataclass(frozen=True)
class ResourceState:
    passed: bool
    reasons: tuple[str, ...]
    metrics: Mapping[str, float | int | None]

    def document(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "reasons": list(self.reasons),
            "metrics": dict(self.metrics),
        }


def _available_memory_bytes() -> int:
    linux_memory = Path("/proc/meminfo")
    if linux_memory.is_file():
        for line in linux_memory.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
        raise OSError("/proc/meminfo does not report MemAvailable")
    if (
        Path("/usr/bin/memory_pressure").is_file()
        and Path("/usr/sbin/sysctl").is_file()
    ):
        pressure = subprocess.run(
            ["/usr/bin/memory_pressure", "-Q"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        total = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "hw.memsize"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        match = re.search(
            r"System-wide memory free percentage:\s*(\d+)%", pressure.stdout
        )
        if pressure.returncode == 0 and total.returncode == 0 and match:
            return int(total.stdout.strip()) * int(match.group(1)) // 100
    raise OSError("available-memory probe is unsupported on this host")


def _temperature_c() -> float | None:
    readings: list[float] = []
    thermal_root = Path("/sys/class/thermal")
    if thermal_root.is_dir():
        for path in thermal_root.glob("thermal_zone*/temp"):
            try:
                value = float(path.read_text(encoding="ascii").strip())
            except (OSError, UnicodeError, ValueError):
                continue
            readings.append(value / 1000 if value > 1000 else value)
    return max(readings) if readings else None


def evaluate_resources(
    policy: ResourcePolicy,
    project_root: Path,
    *,
    memory_bytes: int | None = None,
    free_disk_bytes: int | None = None,
    load_1m: float | None = None,
    logical_cpus: int | None = None,
    temperature_c: float | None = None,
) -> ResourceState:
    gib = 1024**3
    memory = _available_memory_bytes() if memory_bytes is None else memory_bytes
    disk = (
        shutil.disk_usage(project_root).free
        if free_disk_bytes is None
        else free_disk_bytes
    )
    load = os.getloadavg()[0] if load_1m is None else load_1m
    cpus = os.cpu_count() or 1 if logical_cpus is None else logical_cpus
    temperature = _temperature_c() if temperature_c is None else temperature_c
    metrics: dict[str, float | int | None] = {
        "available_memory_gib": round(memory / gib, 3),
        "free_disk_gib": round(disk / gib, 3),
        "load_1m": round(load, 3),
        "logical_cpus": cpus,
        "load_per_cpu": round(load / max(1, cpus), 4),
        "temperature_c": round(temperature, 2) if temperature is not None else None,
    }
    reasons: list[str] = []
    if memory / gib < policy.min_available_memory_gib:
        reasons.append("available-memory-below-minimum")
    if disk / gib < policy.min_free_disk_gib:
        reasons.append("free-disk-below-minimum")
    if policy.max_load_per_cpu and load / max(1, cpus) > policy.max_load_per_cpu:
        reasons.append("load-per-cpu-above-maximum")
    if policy.max_temperature_c:
        if temperature is None:
            reasons.append("temperature-unavailable")
        elif temperature > policy.max_temperature_c:
            reasons.append("temperature-above-maximum")
    return ResourceState(not reasons, tuple(reasons), metrics)


@dataclass(frozen=True)
class NotificationPolicy:
    events: tuple[str, ...] = NOTIFICATION_EVENTS
    outbox: Path | None = None
    webhook_url_env: str | None = None
    webhook_bearer_env: str | None = None
    timeout_seconds: int = 10

    def document(self) -> dict[str, object]:
        return {
            "events": list(self.events),
            "outbox": str(self.outbox) if self.outbox else None,
            "webhook_url_env": self.webhook_url_env,
            "webhook_bearer_env": self.webhook_bearer_env,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class OperationsPolicy:
    schedule: SchedulePolicy
    resources: ResourcePolicy
    notifications: NotificationPolicy

    def document(self) -> dict[str, object]:
        return {
            "schedule": self.schedule.document(),
            "resources": self.resources.document(),
            "notifications": self.notifications.document(),
        }


def evaluate_operations(
    policy: OperationsPolicy,
    project_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    schedule = policy.schedule.evaluate(now)
    resources = evaluate_resources(policy.resources, project_root)
    return {
        "schema_version": "fidb-operations-preflight/v1",
        "checked_at": (now or datetime.now(timezone.utc))
        .astimezone(timezone.utc)
        .isoformat(),
        "ready": schedule.claims_allowed and resources.passed,
        "schedule": schedule.document(),
        "resources": resources.document(),
        "policy": policy.document(),
    }


def load_operations_policy(
    document: Mapping[str, object], project_root: Path
) -> OperationsPolicy:
    schedule_row = _table(document, "schedule")
    _only_keys(
        schedule_row,
        {"enabled", "timezone", "days", "start", "stop_claiming", "hard_cutoff"},
        "schedule table",
    )
    enabled = schedule_row.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("schedule enabled must be a boolean")
    timezone_name = schedule_row.get("timezone", "UTC")
    if not isinstance(timezone_name, str) or not timezone_name:
        raise ValueError("schedule timezone must be a non-empty IANA timezone")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise ValueError(f"unknown schedule timezone: {timezone_name}") from error
    raw_days = schedule_row.get("days", list(DAY_NAMES))
    if (
        not isinstance(raw_days, list)
        or not raw_days
        or any(day not in DAY_NAMES for day in raw_days)
        or len(set(raw_days)) != len(raw_days)
    ):
        raise ValueError(f"schedule days must be unique values from {list(DAY_NAMES)}")
    schedule = SchedulePolicy(
        enabled=enabled,
        timezone_name=timezone_name,
        days=tuple(raw_days),
        start=_clock(schedule_row.get("start", "00:00"), "schedule start"),
        stop_claiming=_clock(
            schedule_row.get("stop_claiming", "23:58"),
            "schedule stop_claiming",
        ),
        hard_cutoff=_clock(
            schedule_row.get("hard_cutoff", "23:59"), "schedule hard_cutoff"
        ),
    )
    schedule._window(date(2026, 1, 1))

    resources_row = _table(document, "resources")
    resource_fields = {
        "min_available_memory_gib",
        "min_free_disk_gib",
        "max_load_per_cpu",
        "max_temperature_c",
    }
    _only_keys(resources_row, resource_fields, "resources table")
    resources = ResourcePolicy(
        **{
            field: _nonnegative_number(
                resources_row.get(field, 0), f"resources {field}"
            )
            for field in resource_fields
        }
    )

    notifications_row = _table(document, "notifications")
    _only_keys(
        notifications_row,
        {
            "events",
            "outbox",
            "webhook_url_env",
            "webhook_bearer_env",
            "timeout_seconds",
        },
        "notifications table",
    )
    raw_events = notifications_row.get("events", list(NOTIFICATION_EVENTS))
    if (
        not isinstance(raw_events, list)
        or any(event not in NOTIFICATION_EVENTS for event in raw_events)
        or len(set(raw_events)) != len(raw_events)
    ):
        raise ValueError(
            "notification events must be unique values from "
            f"{list(NOTIFICATION_EVENTS)}"
        )
    outbox_value = notifications_row.get("outbox")
    outbox = None
    if outbox_value is not None:
        if not isinstance(outbox_value, str) or not outbox_value:
            raise ValueError("notifications outbox must be a relative project path")
        candidate = Path(outbox_value)
        if candidate.is_absolute():
            raise ValueError("notifications outbox must be a relative project path")
        outbox = (project_root / candidate).resolve()
        try:
            outbox.relative_to(project_root.resolve())
        except ValueError as error:
            raise ValueError("notifications outbox escaped the project root") from error
    env_values: dict[str, str | None] = {}
    for field in ("webhook_url_env", "webhook_bearer_env"):
        value = notifications_row.get(field)
        if value is not None and (
            not isinstance(value, str)
            or not value
            or not value.replace("_", "A").isalnum()
            or value.upper() != value
        ):
            raise ValueError(
                f"notifications {field} must name an uppercase environment variable"
            )
        env_values[field] = value
    timeout_seconds = notifications_row.get("timeout_seconds", 10)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 60
    ):
        raise ValueError("notifications timeout_seconds must be 1-60")
    notifications = NotificationPolicy(
        events=tuple(raw_events),
        outbox=outbox,
        webhook_url_env=env_values["webhook_url_env"],
        webhook_bearer_env=env_values["webhook_bearer_env"],
        timeout_seconds=timeout_seconds,
    )
    return OperationsPolicy(schedule, resources, notifications)


def emit_notification(
    policy: NotificationPolicy,
    event: str,
    payload: Mapping[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object] | None:
    if event not in policy.events:
        return None
    occurred = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    document = {
        "schema_version": "fidb-notification/v1",
        "event": event,
        "occurred_at": occurred.isoformat(),
        "payload": dict(payload),
    }
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if policy.outbox is not None:
        policy.outbox.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            policy.outbox,
            os.O_APPEND
            | os.O_CREAT
            | os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError(
                    f"notification outbox is not a regular file: {policy.outbox}"
                )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        parent_descriptor = os.open(
            policy.outbox.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    delivery: dict[str, object] = {
        "outbox": str(policy.outbox) if policy.outbox else None
    }
    if policy.webhook_url_env:
        url = os.environ.get(policy.webhook_url_env)
        if url:
            try:
                if not url.startswith("https://"):
                    raise ValueError("notification webhook must use HTTPS")
                headers = {"Content-Type": "application/json"}
                if policy.webhook_bearer_env:
                    token = os.environ.get(policy.webhook_bearer_env)
                    if token:
                        headers["Authorization"] = f"Bearer {token}"
                request = Request(
                    url, data=encoded.rstrip(), headers=headers, method="POST"
                )
                with urlopen(request, timeout=policy.timeout_seconds) as response:
                    delivery["webhook_status"] = response.status
            except Exception as error:  # notification failure cannot corrupt a lease
                delivery["webhook_error"] = f"{type(error).__name__}: {error}"
    return delivery
