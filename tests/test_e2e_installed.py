from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
from typing import Any, Dict
import pytest

MCP_INTEGRITY_BIN = os.environ.get("MCP_INTEGRITY_BIN")
pytestmark = pytest.mark.skipif(
    not MCP_INTEGRITY_BIN,
    reason="MCP_INTEGRITY_BIN not set (requires installed mcp-integrity binary)",
)


def _send_and_recv_line(proc: subprocess.Popen, req: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    """Send a JSON-RPC request line and read one response line with a timeout."""
    assert proc.stdin is not None
    assert proc.stdout is not None

    line = json.dumps(req) + "\n"
    proc.stdin.write(line.encode("utf-8"))
    proc.stdin.flush()

    q: queue.Queue[bytes] = queue.Queue()

    def reader():
        res = proc.stdout.readline()
        q.put(res)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    try:
        raw = q.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError(f"Timed out waiting {timeout}s for response to {req.get('method')}")

    if not raw:
        stderr_output = ""
        if proc.stderr:
            try:
                stderr_output = proc.stderr.read().decode("utf-8")
            except Exception:
                pass
        raise EOFError(f"Process stdout closed unexpectedly. stderr: {stderr_output}")

    return json.loads(raw.decode("utf-8"))


def test_e2e_real_user_workflow(tmp_path: Path):
    """End-to-end simulation of a real user:
    a) init wraps Claude Desktop config
    b) Client restart simulation spawns wrapped server, calls tools, checks replies
    c) status reports protected server and logged call
    d) enforce blocks unlisted tool calls with -32001
    e) uninstall cleanly restores original config
    """
    mcp_integrity_bin = os.path.abspath(MCP_INTEGRITY_BIN)
    assert os.path.exists(mcp_integrity_bin), f"MCP_INTEGRITY_BIN does not exist: {mcp_integrity_bin}"

    tmp_home = tmp_path / "home"
    tmp_guard_home = tmp_path / "guard_home"
    tmp_home.mkdir(parents=True, exist_ok=True)
    tmp_guard_home.mkdir(parents=True, exist_ok=True)

    # 1. Prepare Claude Desktop config
    if sys.platform == "darwin":
        claude_dir = tmp_home / "Library" / "Application Support" / "Claude"
    else:
        claude_dir = tmp_home / ".config" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = claude_dir / "claude_desktop_config.json"

    fake_server_path = (Path(__file__).resolve().parent / "fake_server.py").resolve()
    assert fake_server_path.exists(), f"fake_server.py not found at {fake_server_path}"

    original_config = {
        "mcpServers": {
            "demo_server": {
                "command": sys.executable,
                "args": [str(fake_server_path)],
            }
        }
    }
    cfg_path.write_text(json.dumps(original_config, indent=2), encoding="utf-8")

    cli_env = {
        "HOME": str(tmp_home),
        "MCP_INTEGRITY_HOME": str(tmp_guard_home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }

    # a) $MCP_INTEGRITY_BIN init -> exit 0; config entry command is absolute and exists; .bak created
    res_init = subprocess.run([mcp_integrity_bin, "init"], env=cli_env, capture_output=True, text=True)
    assert res_init.returncode == 0, f"init failed: stdout={res_init.stdout}, stderr={res_init.stderr}"

    init_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    srv_entry = init_cfg["mcpServers"]["demo_server"]
    cmd_path = Path(srv_entry["command"])
    assert cmd_path.is_absolute(), f"command is not absolute: {cmd_path}"
    assert cmd_path.exists(), f"command does not exist: {cmd_path}"

    bak_path = Path(f"{cfg_path}.mcp-integrity.bak")
    assert bak_path.exists(), "Backup .mcp-integrity.bak was not created"
    assert json.loads(bak_path.read_text(encoding="utf-8")) == original_config

    # b) Restart simulation: spawn wrapped server exactly as client would
    # GUI clients do not inherit shell PATH, so use PATH=/usr/bin:/bin
    spawn_env = {
        "HOME": str(tmp_home),
        "MCP_INTEGRITY_HOME": str(tmp_guard_home),
        "PATH": "/usr/bin:/bin",
    }
    spawn_cmd = [srv_entry["command"], *srv_entry.get("args", [])]
    proc = subprocess.Popen(
        spawn_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=spawn_env,
    )

    try:
        # Send initialize
        init_resp = _send_and_recv_line(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"capabilities": {}},
        })
        assert init_resp.get("id") == 1
        assert "result" in init_resp

        # Send tools/list
        list_resp = _send_and_recv_line(proc, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })
        assert list_resp.get("id") == 2
        tools = list_resp.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        assert "search" in tool_names
        assert "send_email" in tool_names

        # Send valid tools/call
        call_resp = _send_and_recv_line(proc, {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "audit test query"},
            },
        })
        assert call_resp.get("id") == 3
        assert "result" in call_resp
    finally:
        # Close stdin and wait for proxy to shut down child
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5.0)

    # c) $MCP_INTEGRITY_BIN status -> contains "protected (1): Claude Desktop/<name>" and "last 24h: 1 calls"
    res_status = subprocess.run([mcp_integrity_bin, "status"], env=cli_env, capture_output=True, text=True)
    assert res_status.returncode == 0, f"status failed: {res_status.stderr}"
    assert "protected (1): Claude Desktop/demo_server" in res_status.stdout
    assert "last 24h: 1 calls" in res_status.stdout

    # d) $MCP_INTEGRITY_BIN enforce -> exit 0, config args contain "--mode","enforce".
    res_enforce = subprocess.run([mcp_integrity_bin, "enforce"], env=cli_env, capture_output=True, text=True)
    assert res_enforce.returncode == 0, f"enforce failed: {res_enforce.stderr}"

    enforce_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    enforce_args = enforce_cfg["mcpServers"]["demo_server"]["args"]
    assert "--mode" in enforce_args
    mode_idx = enforce_args.index("--mode")
    assert enforce_args[mode_idx + 1] == "enforce"

    # Spawn again: tools/list, then unlisted tools/call -> JSON-RPC error -32001 and "unknown_tool"
    proc_enforce = subprocess.Popen(
        [enforce_cfg["mcpServers"]["demo_server"]["command"], *enforce_args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=spawn_env,
    )

    try:
        # First send tools/list so the guard learns the manifest
        list_resp_e = _send_and_recv_line(proc_enforce, {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/list",
            "params": {},
        })
        assert list_resp_e.get("id") == 10

        # Now send tools/call to an unlisted tool
        blocked_resp = _send_and_recv_line(proc_enforce, {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "unlisted_malicious_tool",
                "arguments": {},
            },
        })
        assert blocked_resp.get("id") == 11
        assert "error" in blocked_resp, f"Expected error response, got {blocked_resp}"
        assert blocked_resp["error"]["code"] == -32001
        assert "unknown_tool" in blocked_resp["error"]["message"]
    finally:
        if proc_enforce.stdin:
            proc_enforce.stdin.close()
        proc_enforce.wait(timeout=5.0)

    # e) $MCP_INTEGRITY_BIN uninstall -> exit 0; config JSON equals original (parsed-equal)
    res_uninstall = subprocess.run([mcp_integrity_bin, "uninstall"], env=cli_env, capture_output=True, text=True)
    assert res_uninstall.returncode == 0, f"uninstall failed: {res_uninstall.stderr}"

    final_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert final_cfg == original_config
