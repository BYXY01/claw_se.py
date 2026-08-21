"""Ladder 2: basic modules - exec / file(.bak+rollback) / info, all secured."""
from modules.core.security import protected_dirs
from modules.core.security.rules import Rules
from modules.core.security.store import Store
from modules.core.security.wrapper import SecurityConfig, SecurityContext, secure_tool


def make_ctx(security_config, app_root):
    store = Store(security_config, app_root)
    rules = Rules(store, protected_dirs(app_root))
    cfg = SecurityConfig.from_dict(security_config)
    return SecurityContext(store, rules, cfg, judge=None)


# ---------------- exec ----------------
def test_exec_run_command(tmp_path, security_config):
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(execute, "command", ctx)
    out = secured.invoke({"operation": "run", "command": "echo hello-from-sec"})
    assert "hello-from-sec" in out


def test_exec_run_timeout_prevents_hang(tmp_path, security_config):
    """Foreground run must time out instead of blocking forever."""
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(execute, "command", ctx)
    out = secured.invoke({"operation": "run", "command": "sleep 10", "timeout": 1})
    assert "timed out" in out


def test_exec_blacklisted_blocked(tmp_path, security_config):
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    ctx.store.add("rm -rf", "blacklist")
    secured = secure_tool(execute, "command", ctx)
    out = secured.invoke({"operation": "run", "command": "rm -rf /tmp/evil"})
    assert "Blocked (blacklist hit)" in out


def test_exec_self_dir_guard(tmp_path, security_config):
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(execute, "command", ctx)
    out = secured.invoke({"operation": "run", "command": "rm modules/exec.py"})
    assert "self-directory guard" in out


def test_exec_background_input_not_checked(tmp_path, security_config):
    """fix #8: background `input` bypasses the command check (user confirmed target)."""
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    ctx.store.add("rm -rf", "blacklist")
    secured = secure_tool(execute, "command", ctx)
    # command is empty for input -> not classified, only the missing pid matters
    out = secured.invoke({"operation": "input", "pid": 999, "input_text": "rm -rf /"})
    assert "Process 999 not found" in out
    assert "Blocked" not in out


def test_exec_background_lifecycle(tmp_path, security_config):
    from modules.exec import execute
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(execute, "command", ctx)
    start = secured.invoke({"operation": "start", "command": "sleep 5"})
    assert "PID: 1" in start
    listing = secured.invoke({"operation": "list"})
    assert "sleep 5" in listing
    status = secured.invoke({"operation": "status", "pid": 1})
    assert "PID: 1" in status
    stop = secured.invoke({"operation": "stop", "pid": 1})
    assert "stopped" in stop


def test_exec_stop_kills_process_tree():
    """stop must kill the whole shell tree, not just the shell (shell=True bug)."""
    import os
    import time
    from modules.exec import _processes, _start_process, _stop_process

    if os.name == "nt":
        return  # POSIX process-group semantics; Windows uses psutil

    _processes.clear()
    _start_process("sleep 200 & sleep 100")  # sh spawns two children
    pid = max(_processes)
    pgid = os.getpgid(_processes[pid]["process"].pid)
    _stop_process(pid)

    import psutil
    leftovers = []
    deadline = time.time() + 2.0
    while time.time() < deadline:
        leftovers = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                pr = psutil.Process(int(entry))
                if pr.status() == psutil.STATUS_ZOMBIE:
                    continue  # dead but not yet reaped; not actually running
                if os.getpgid(int(entry)) == pgid:
                    leftovers.append(entry)
            except (ProcessLookupError, PermissionError, OSError):
                continue
        if not leftovers:
            break
        time.sleep(0.1)
    assert leftovers == [], f"process tree not killed, leftovers: {leftovers}"


# ---------------- file ----------------
def test_file_write_read(tmp_path, security_config):
    from modules.file import file_op
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(file_op, "path", ctx)
    target = tmp_path / "note.txt"
    out = secured.invoke({"path": str(target), "operation": "write", "content": "v1"})
    assert "written" in out
    read = secured.invoke({"path": str(target), "operation": "read"})
    assert read == "v1"


def test_file_write_backup_and_rollback(tmp_path, security_config):
    """fix #10: write creates a .bak; rollback restores the previous content."""
    from modules.file import file_op
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(file_op, "path", ctx)
    target = tmp_path / "data.txt"
    target.write_text("original", encoding="utf-8")

    secured.invoke({"path": str(target), "operation": "write", "content": "changed"})
    bak = tmp_path / "data.txt.bak"
    assert bak.exists()
    assert bak.read_text(encoding="utf-8") == "original"

    rollback = secured.invoke({"path": str(target), "operation": "rollback"})
    assert "Rolled back" in rollback
    assert target.read_text(encoding="utf-8") == "original"


def test_file_self_dir_guard(tmp_path, security_config):
    from modules.file import file_op
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(file_op, "path", ctx)
    out = secured.invoke({"path": "modules/exec.py", "operation": "write", "content": "x"})
    assert "self-directory guard" in out


def test_file_blacklisted_path_blocked(tmp_path, security_config):
    from modules.file import file_op
    ctx = make_ctx(security_config, tmp_path)
    ctx.store.add("/etc/passwd", "blacklist")
    secured = secure_tool(file_op, "path", ctx)
    out = secured.invoke({"path": "/etc/passwd", "operation": "read"})
    assert "Blocked (blacklist hit)" in out


def test_file_replace_line_range(tmp_path, security_config):
    """replace swaps an inclusive 1-based line range with new content (.bak kept)."""
    from modules.file import file_op
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(file_op, "path", ctx)
    target = tmp_path / "src.txt"
    target.write_text("a\nb\nc\nd\n", encoding="utf-8")
    out = secured.invoke({"path": str(target), "operation": "replace",
                          "start_line": 2, "end_line": 3, "content": "X\nY"})
    assert "Replaced lines 2-3" in out
    assert target.read_text(encoding="utf-8") == "a\nX\nY\nd\n"
    # single-line replace via start_line only
    secured.invoke({"path": str(target), "operation": "replace", "start_line": 1, "content": "A"})
    assert target.read_text(encoding="utf-8") == "A\nX\nY\nd\n"
    # out-of-range rejected
    bad = secured.invoke({"path": str(target), "operation": "replace",
                          "start_line": 5, "content": "z"})
    assert "invalid line range" in bad


# ---------------- info ----------------
def test_info_returns_system_info(tmp_path, security_config):
    from modules.info import get_info
    ctx = make_ctx(security_config, tmp_path)
    secured = secure_tool(get_info, None, ctx)
    out = secured.invoke({})
    assert "system:" in out
    assert "python_version:" in out
