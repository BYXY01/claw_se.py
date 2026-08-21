"""Unified executor: foreground commands + background process management.

- execute(command, operation, ...) is a single entry: run / start / input / stop / status / list.
- run and start go through the security wrapper (guard_key="command"); additionally a
  self-directory guard runs here right before execution as defense in depth (fix #13).
- background `input` is intentionally NOT security-checked (fix #8): the user has already
  confirmed the target process when it was started.
"""
import os
import signal
import subprocess
import threading
import time
from typing import Optional

from langchain_core.tools import tool

from .core import config as core_config
from .core import env
from .core.security import protected_dirs
from .core.security.rules import self_dir_match

# process registry (internal PID -> info)
_processes: dict[int, dict] = {}
_next_pid: int = 1


def _check_self_dir(command: str) -> Optional[str]:
    """Run the self-directory guard against a command (defense in depth, fix #13)."""
    return self_dir_match(command, protected_dirs(core_config.app_root()))


def _start_process(command: str) -> str:
    """Start a background process.

    Args:
        command: shell command to run in the background.

    Returns:
        Status message including the assigned PID.
    """
    global _next_pid

    kwargs = dict(
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    # start in its OWN process group/session so stop can signal the whole tree
    # (with shell=True, Popen is only the shell; killing the shell alone would
    #  orphan the actual command - that is why the group is required)
    if env.IS_WIN:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    process = subprocess.Popen(command, **kwargs)

    pid = _next_pid
    _next_pid += 1

    _processes[pid] = {
        "process": process,
        "command": command,
        "start_time": time.time(),
        "status": "running",
    }

    def read_output(proc, pid):
        while True:
            line = proc.stdout.readline()
            if line:
                print(f"[PID:{pid}] {line.strip()}")
            else:
                break

    thread = threading.Thread(target=read_output, args=(process, pid), daemon=True)
    thread.start()

    return (
        f"Process started with PID: {pid} | Command: {command}\n"
        f"Use execute with operation='input' to send input, operation='stop' to stop it."
    )


def _input_process(pid: int, input_text: str) -> str:
    """Send input to a background process (no security check, fix #8).

    Args:
        pid: the internal PID.
        input_text: text to write to the process stdin.

    Returns:
        Status message.
    """
    if pid not in _processes:
        return f"Error: Process {pid} not found"
    try:
        _processes[pid]["process"].stdin.write(input_text + "\n")
        _processes[pid]["process"].stdin.flush()
        return f"Input sent to process {pid}: {input_text}"
    except Exception as e:
        return f"Error sending input: {e}"


def _kill_tree(proc, force: bool) -> None:
    """Signal the whole process tree (the shell AND its children).

    With shell=True the Popen object is only the shell; signaling the shell alone
    would orphan the actual command. Each background process runs in its own group
    (see _start_process), so we signal the whole group:
    - POSIX : os.killpg on the session created by start_new_session
    - Windows: taskkill /T on the group created by CREATE_NEW_PROCESS_GROUP
    """
    if env.IS_WIN:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True, check=False)
        return
    sig = signal.SIGKILL if force else signal.SIGTERM
    os.killpg(os.getpgid(proc.pid), sig)


def _stop_process(pid: int) -> str:
    """Stop a background process (the whole process tree).

    Args:
        pid: the internal PID.

    Returns:
        Status message.
    """
    if pid not in _processes:
        return f"Error: Process {pid} not found"
    info = _processes[pid]
    proc = info["process"]
    try:
        _kill_tree(proc, force=False)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill_tree(proc, force=True)
            proc.wait(timeout=5)
        info["status"] = "stopped"
        return f"Process {pid} stopped"
    except ProcessLookupError:
        info["status"] = "stopped"
        return f"Process {pid} already exited"
    except Exception as e:
        try:
            _kill_tree(proc, force=True)
            info["status"] = "killed"
            return f"Process {pid} killed"
        except Exception:
            return f"Error stopping process: {e}"


def _process_status(pid: int) -> str:
    """Get the status of a background process.

    Args:
        pid: the internal PID.

    Returns:
        Status message.
    """
    if pid not in _processes:
        return f"Error: Process {pid} not found"
    info = _processes[pid]
    if info["status"] == "running":
        running = f"{time.time() - info['start_time']:.1f}s"
    else:
        running = "N/A"
    return (
        f"PID: {pid} | Command: {info['command']} | "
        f"Status: {info['status']} | Running: {running}"
    )


def _process_list() -> str:
    """List all tracked background processes.

    Returns:
        Multi-line status message.
    """
    if not _processes:
        return "No processes running"
    lines = []
    for pid, info in _processes.items():
        if info["status"] == "running":
            running = f"{time.time() - info['start_time']:.1f}s"
            lines.append(f"PID: {pid} | Status: running | Running: {running} | {info['command']}")
        else:
            lines.append(f"PID: {pid} | Status: {info['status']} | {info['command']}")
    return "Processes:\n" + "\n".join(lines)


_DEFAULT_RUN_TIMEOUT = 30  # seconds; foreground run must never block forever


@tool
def execute(command: str = "", operation: str = "run", pid: Optional[int] = None,
            input_text: str = "", timeout: int = _DEFAULT_RUN_TIMEOUT) -> str:
    """Unified executor: run commands or manage background processes.

    Args:
        command: command to execute (used by operation='run'/'start').
        operation: operation type:
            - 'run': run a command in the foreground and return its output (default)
            - 'start': start a background process
            - 'input': send input to a background process (not security-checked, fix #8)
            - 'stop': stop a background process
            - 'status': show a background process status
            - 'list': list all background processes
        pid: background process ID (used by 'input'/'stop'/'status').
        input_text: input to send to a background process (used by 'input').
        timeout: max seconds a foreground 'run' may take (default 30) so it can
            never block the agent indefinitely. Background 'start' is
            non-blocking (Popen) and unaffected by this timeout.

    Returns:
        Command output or a status/error message.
    """
    try:
        if operation == "run":
            if not command:
                return "Error: 'command' parameter required for run operation"
            blocked = _check_self_dir(command)
            if blocked:
                return f"[SE] Blocked (self-directory guard): {blocked}"
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return f"[SE] Command timed out after {timeout}s (blocked to prevent hang)."
            return (result.stdout + result.stderr).strip() or "(no output)"

        if operation == "start":
            if not command:
                return "Error: 'command' parameter required for start operation"
            blocked = _check_self_dir(command)
            if blocked:
                return f"[SE] Blocked (self-directory guard): {blocked}"
            return _start_process(command)

        if operation == "input":
            if pid is None:
                return "Error: 'pid' parameter required for input operation"
            return _input_process(pid, input_text)

        if operation == "stop":
            if pid is None:
                return "Error: 'pid' parameter required for stop operation"
            return _stop_process(pid)

        if operation == "status":
            if pid is None:
                return "Error: 'pid' parameter required for status operation"
            return _process_status(pid)

        if operation == "list":
            return _process_list()

        return (
            f"Error: Unknown operation '{operation}'. "
            f"Supported: run, start, input, stop, status, list"
        )
    except Exception as e:
        return f"Error: {e}"


FEATURE = {
    "name": "exec",
    "version": "0.1",
    "desc": "Unified executor: foreground command + background process management",
    "tools": [execute],
    "hooks": {},
    "guard_key": "command",
}
