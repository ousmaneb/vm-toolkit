"""Install `vmt daily` with the operating system's scheduler: launchd on macOS, cron on Linux, Task Scheduler on Windows."""

import os
import plistlib
import subprocess
import sys
from pathlib import Path

from .config import ConfigError, Settings

LABEL = "com.vmtoolkit.daily"
CRON_MARK = "# vmtoolkit-daily"
TASK_NAME = "vmtoolkit daily"


def parse_time(text: str) -> tuple[int, int]:
    try:
        hour, minute = (int(part) for part in text.split(":"))
    except ValueError:
        raise ConfigError(f"--time must look like 07:00, not {text!r}") from None
    if not (0 <= hour < 24 and 0 <= minute < 60):
        raise ConfigError(f"--time must look like 07:00, not {text!r}")
    return hour, minute


def command(settings: Settings) -> list[str]:
    """Always the configured database: a schedule pointed at demo data would be easy to forget about."""
    config = settings.base_dir / "config.toml"
    if not config.exists():
        raise ConfigError(f"No config.toml in {settings.base_dir}. Run `vmt init` first.")
    return [sys.executable, "-m", "vmtoolkit", "--config", str(config), "daily"]


def launchd_plist(cmd: list[str], hour: int, minute: int, log: Path, workdir: Path) -> bytes:
    return plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": cmd,
        "WorkingDirectory": str(workdir),
        "StartCalendarInterval": {"Hour": hour, "Minute": minute},
        "StandardOutPath": str(log),
        "StandardErrorPath": str(log),
    })


def cron_line(cmd: list[str], hour: int, minute: int, log: Path) -> str:
    quoted = " ".join(f"'{part}'" for part in cmd)
    return f"{minute} {hour} * * * {quoted} >> '{log}' 2>&1 {CRON_MARK}"


def windows_script(cmd: list[str], log: Path) -> str:
    # schtasks limits /TR to 261 characters, so the task runs this small script instead.
    return "@echo off\r\n" + " ".join(f'"{part}"' for part in cmd) + f' >> "{log}" 2>&1\r\n'


def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, text=True, **kwargs)
    except FileNotFoundError:
        # For example a minimal Linux install without cron.
        return subprocess.CompletedProcess(args, 127, "", f"{args[0]} is not installed")


def install(settings: Settings, time: str) -> str:
    hour, minute = parse_time(time)
    cmd = command(settings)
    log = settings.data_dir / "logs" / "scheduler.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        path = _plist_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(launchd_plist(cmd, hour, minute, log, settings.base_dir))
        domain = f"gui/{os.getuid()}"
        _run(["launchctl", "bootout", domain, str(path)])  # replaces an older install; fails harmlessly if none
        done = _run(["launchctl", "bootstrap", domain, str(path)])
        if done.returncode != 0:
            raise ConfigError(f"launchctl could not load {path}: {done.stderr.strip()}")
        where = f"launchd ({path})"
    elif sys.platform == "win32":
        script = settings.data_dir / "vmtoolkit-daily.cmd"
        script.write_text(windows_script(cmd, log), encoding="utf-8")
        done = _run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", f"{hour:02d}:{minute:02d}",
                     "/TN", TASK_NAME, "/TR", f'"{script}"'])
        if done.returncode != 0:
            raise ConfigError(f"schtasks failed: {done.stderr.strip() or done.stdout.strip()}")
        where = f'Task Scheduler ("{TASK_NAME}")'
    else:
        current = _run(["crontab", "-l"])
        lines = [line for line in current.stdout.splitlines() if CRON_MARK not in line] if current.returncode == 0 else []
        lines.append(cron_line(cmd, hour, minute, log))
        done = _run(["crontab", "-"], input="\n".join(lines) + "\n")
        if done.returncode != 0:
            raise ConfigError(f"crontab failed: {done.stderr.strip()}")
        where = "your crontab"
    return (f"Installed: `vmt daily` runs every day at {hour:02d}:{minute:02d} via {where}, "
            f"on {settings.data_dir / 'vmt.db'}. Scheduler output goes to {log}.")


def remove() -> str:
    if sys.platform == "darwin":
        path = _plist_path()
        if not path.exists():
            return "Not installed."
        _run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)])
        path.unlink()
    elif sys.platform == "win32":
        if _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME]).returncode != 0:
            return "Not installed."
    else:
        current = _run(["crontab", "-l"])
        if current.returncode != 0 or CRON_MARK not in current.stdout:
            return "Not installed."
        kept = [line for line in current.stdout.splitlines() if CRON_MARK not in line]
        _run(["crontab", "-"], input="\n".join(kept) + "\n" if kept else "")
    return "Removed the daily schedule."


def status() -> str:
    if sys.platform == "darwin":
        path = _plist_path()
        if not path.exists():
            return "Not installed."
        info = plistlib.loads(path.read_bytes())
        when = info["StartCalendarInterval"]
        loaded = _run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"]).returncode == 0
        return (f"Installed: every day at {when['Hour']:02d}:{when['Minute']:02d} via launchd"
                + ("." if loaded else ", but not loaded. Run `vmt schedule install` again."))
    if sys.platform == "win32":
        done = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST"])
        return done.stdout.strip() if done.returncode == 0 else "Not installed."
    current = _run(["crontab", "-l"])
    line = next((x for x in current.stdout.splitlines() if CRON_MARK in x), None) if current.returncode == 0 else None
    if not line:
        return "Not installed."
    minute, hour = line.split()[:2]
    return f"Installed: every day at {int(hour):02d}:{int(minute):02d} via cron."
