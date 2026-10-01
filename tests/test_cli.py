from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import pytest

from mcp_integrity.cli import main
from mcp_integrity.clients import is_wrapped_server
from mcp_integrity.config import get_guard_home


def test_init_fake_claude_desktop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_home = tmp_path / "user_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    claude_dir = fake_home / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = claude_dir / "claude_desktop_config.json"

    original_obj = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/samir/Desktop"],
                "env": {"TEST_VAR": "secret"},
            },
            "github": {
                "command": "docker",
                "args": ["run", "-i", "--rm", "mcp/github"],
            },
            "linear": {
                "url": "https://mcp.linear.app/sse",
            },
        }
    }
    original_bytes = json.dumps(original_obj, indent=2).encode("utf-8")
    cfg_file.write_bytes(original_bytes)

    # 1. Run init
    rc = main(["init"])
    assert rc == 0
    out, _ = capsys.readouterr()

    # Output verification
    assert "wrapped   filesystem" in out
    assert "wrapped   github" in out
    assert "skipped   linear (remote server)" in out
    assert "2 servers protected in audit mode" in out

    # Verify .bak
    bak_file = Path(f"{cfg_file}.mcp-integrity.bak")
    assert bak_file.exists()
    assert bak_file.read_bytes() == original_bytes

    # Verify config modifications
    data = json.loads(cfg_file.read_text(encoding="utf-8"))
    fs_srv = data["mcpServers"]["filesystem"]
    gh_srv = data["mcpServers"]["github"]
    lin_srv = data["mcpServers"]["linear"]

    # filesystem wrapped
    assert "mcp-integrity" in fs_srv["command"]
    assert os.path.isabs(fs_srv["command"])
    assert is_wrapped_server(fs_srv)
    assert fs_srv["args"] == [
        "run",
        "--name",
        "filesystem",
        "--mode",
        "audit",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/samir/Desktop",
    ]
    assert fs_srv["env"] == {"TEST_VAR": "secret"}

    # github wrapped
    assert "mcp-integrity" in gh_srv["command"]
    assert os.path.isabs(gh_srv["command"])
    assert is_wrapped_server(gh_srv)
    assert gh_srv["args"] == [
        "run",
        "--name",
        "github",
        "--mode",
        "audit",
        "--",
        "docker",
        "run",
        "-i",
        "--rm",
        "mcp/github",
    ]

    # remote skipped
    assert lin_srv == {"url": "https://mcp.linear.app/sse"}

    # Second init is a no-op and does not touch .bak
    bak_mtime = bak_file.stat().st_mtime_ns
    rc2 = main(["init"])
    assert rc2 == 0
    out2, _ = capsys.readouterr()
    assert "already wrapped   filesystem" in out2
    assert "already wrapped   github" in out2
    assert "skipped   linear (remote server)" in out2
    assert bak_file.read_bytes() == original_bytes
    assert bak_file.stat().st_mtime_ns == bak_mtime


def test_uninstall_restores_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_home = tmp_path / "user_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    claude_dir = fake_home / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = claude_dir / "claude_desktop_config.json"

    original_obj = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "server-fs"],
            },
            "github": {
                "command": "docker",
                "args": ["run", "-i"],
            },
            "linear": {
                "url": "https://mcp.linear.app/sse",
            },
        }
    }
    cfg_file.write_text(json.dumps(original_obj, indent=2), encoding="utf-8")

    # Wrap them first
    assert main(["init"]) == 0
    capsys.readouterr()

    # Now run uninstall
    rc = main(["uninstall"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "unwrapped   filesystem" in out
    assert "unwrapped   github" in out
    assert "2 servers restored to original configuration" in out

    # Verify restored config exactly matches original parsed JSON
    restored = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert restored == original_obj


def test_enforce_and_audit_mode_switch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_home = tmp_path / "user_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    claude_dir = fake_home / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = claude_dir / "claude_desktop_config.json"

    original_obj = {
        "mcpServers": {
            "srv": {
                "command": "srv_cmd",
                "args": ["arg1"],
            }
        }
    }
    cfg_file.write_text(json.dumps(original_obj, indent=2), encoding="utf-8")
    assert main(["init"]) == 0
    capsys.readouterr()

    # 1. Switch to enforce
    rc_enforce = main(["enforce"])
    assert rc_enforce == 0
    out_e, _ = capsys.readouterr()
    assert "1 servers switched to enforce mode" in out_e

    # Verify config args has --mode enforce
    data_e = json.loads(cfg_file.read_text(encoding="utf-8"))
    args_e = data_e["mcpServers"]["srv"]["args"]
    mode_idx = args_e.index("--mode")
    assert args_e[mode_idx + 1] == "enforce"

    # Verify guard home config.json
    guard_home = get_guard_home()
    cfg_json = json.loads((guard_home / "config.json").read_text(encoding="utf-8"))
    assert cfg_json["mode"] == "enforce"

    # 2. Switch to audit
    rc_audit = main(["audit"])
    assert rc_audit == 0
    out_a, _ = capsys.readouterr()
    assert "1 servers switched to audit mode" in out_a

    # Verify config args has --mode audit
    data_a = json.loads(cfg_file.read_text(encoding="utf-8"))
    args_a = data_a["mcpServers"]["srv"]["args"]
    mode_idx = args_a.index("--mode")
    assert args_a[mode_idx + 1] == "audit"

    # Verify guard home config.json
    cfg_json = json.loads((guard_home / "config.json").read_text(encoding="utf-8"))
    assert cfg_json["mode"] == "audit"


def test_status_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    guard_home = tmp_path / "mcp_integrity_home"
    guard_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MCP_INTEGRITY_HOME", str(guard_home))

    fake_home = tmp_path / "user_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    # Empty log and no configs initially -> servers: none found
    rc = main(["status"])
    assert rc == 0
    out_empty, _ = capsys.readouterr()
    assert "servers: none found" in out_empty
    assert "no calls logged yet — is your client restarted?" in out_empty

    # Create real executable file named mcp-integrity in tmp
    real_launcher = tmp_path / "bin" / "mcp-integrity"
    real_launcher.parent.mkdir(parents=True, exist_ok=True)
    real_launcher.write_text("#!/bin/sh\nexit 0\n")
    real_launcher.chmod(0o755)

    # Create fixture client configs with:
    # 1. one wrapped whose command is a real executable file named mcp-integrity (chmod +x)
    # 2. one unwrapped
    # 3. one remote (url)
    # 4. one wrapped whose command path does not exist
    claude_dir = fake_home / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = claude_dir / "claude_desktop_config.json"
    broken_cmd = str(tmp_path / "nonexistent" / "mcp-integrity")
    cfg_data = {
        "mcpServers": {
            "wrapped_ok": {
                "command": str(real_launcher),
                "args": ["run", "--name", "wrapped_ok", "--", "node", "ok.js"],
            },
            "unwrapped_srv": {
                "command": "node",
                "args": ["unwrapped.js"],
            },
            "remote_srv": {
                "url": "https://example.com/sse",
            },
            "wrapped_broken": {
                "command": broken_cmd,
                "args": ["run", "--name", "wrapped_broken", "--", "node", "broken.js"],
            },
        }
    }
    cfg_file.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")

    # Create synthetic audit.jsonl
    now_iso = datetime.now(timezone.utc).isoformat()
    lines = [
        # Benign allowed call
        json.dumps({
            "ts": now_iso,
            "server": "wrapped_ok",
            "tool": "read_file",
            "argument_keys": ["path"],
            "allowed": True,
            "rule": "allow",
        }),
        # 3 calls that would block
        json.dumps({
            "ts": now_iso,
            "server": "wrapped_broken",
            "tool": "delete_repo",
            "argument_keys": ["repo"],
            "allowed": False,
            "rule": "unknown_tool",
        }),
        json.dumps({
            "ts": now_iso,
            "server": "wrapped_broken",
            "tool": "delete_repo",
            "argument_keys": ["repo"],
            "allowed": False,
            "rule": "unknown_tool",
        }),
        json.dumps({
            "ts": now_iso,
            "server": "wrapped_broken",
            "tool": "delete_repo",
            "argument_keys": ["repo"],
            "allowed": False,
            "rule": "unknown_tool",
        }),
        # Suspicious description
        json.dumps({
            "ts": now_iso,
            "server": "wrapped_ok",
            "tool": "read_file",
            "argument_keys": [],
            "allowed": True,
            "rule": "suspicious_description",
            "findings": ["hidden_instruction"],
        }),
        # Tool changed
        json.dumps({
            "ts": now_iso,
            "server": "postgres",
            "tool": "query",
            "argument_keys": [],
            "allowed": True,
            "rule": "tool_changed",
        }),
    ]
    (guard_home / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Add a pin file for postgres
    pins_dir = guard_home / "pins"
    pins_dir.mkdir(parents=True, exist_ok=True)
    (pins_dir / "postgres.json").write_text(
        json.dumps({
            "query": {"first_seen": now_iso, "sha256": "abc", "observed_sha256": "def"}
        }),
        encoding="utf-8",
    )

    rc = main(["status"])
    assert rc == 0
    out, _ = capsys.readouterr()

    assert "mode: audit" in out
    assert "protected (1): Claude Desktop/wrapped_ok" in out
    assert "unprotected (1): Claude Desktop/unwrapped_srv   run 'mcp-integrity init' to protect" in out
    assert "broken (1): Claude Desktop/wrapped_broken   launcher not found; re-run 'mcp-integrity init'" in out
    assert "remote, not covered (1): Claude Desktop/remote_srv" in out
    assert "4 calls" in out
    assert "3 would-block" in out
    assert "1 suspicious description" in out
    assert "1 changed tools" in out
    assert "wrapped_broken   delete_repo   unknown_tool   x3" in out
    assert "wrapped_ok   read_file   hidden_instruction" in out
    assert "postgres   query" in out


def test_vscode_and_claude_code_schemas(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_home = tmp_path / "user_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    # VS Code config (~/.vscode/mcp.json) using 'servers' key
    vscode_dir = fake_home / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    vscode_file = vscode_dir / "mcp.json"
    vscode_file.write_text(
        json.dumps({
            "servers": {
                "vsc_srv": {"command": "node", "args": ["index.js"]}
            }
        }, indent=2),
        encoding="utf-8",
    )

    # Claude Code config (~/.claude.json) using 'mcpServers' and 'projects.<path>.mcpServers'
    claude_file = fake_home / ".claude.json"
    proj_path = str(tmp_path / "my_project")
    claude_file.write_text(
        json.dumps({
            "mcpServers": {
                "global_srv": {"command": "global_cmd", "args": ["--global"]}
            },
            "projects": {
                proj_path: {
                    "mcpServers": {
                        "proj_srv": {"command": "proj_cmd", "args": ["--proj"]}
                    }
                }
            },
        }, indent=2),
        encoding="utf-8",
    )

    # Run init
    rc = main(["init"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert "wrapped   vsc_srv" in out
    assert "wrapped   global_srv" in out
    assert "wrapped   proj_srv" in out

    # Verify VS Code wrapping
    vsc_data = json.loads(vscode_file.read_text(encoding="utf-8"))
    assert "mcp-integrity" in vsc_data["servers"]["vsc_srv"]["command"]
    assert vsc_data["servers"]["vsc_srv"]["args"] == [
        "run",
        "--name",
        "vsc_srv",
        "--mode",
        "audit",
        "--",
        "node",
        "index.js",
    ]

    # Verify Claude Code wrapping
    cc_data = json.loads(claude_file.read_text(encoding="utf-8"))
    assert "mcp-integrity" in cc_data["mcpServers"]["global_srv"]["command"]
    assert cc_data["mcpServers"]["global_srv"]["args"] == [
        "run",
        "--name",
        "global_srv",
        "--mode",
        "audit",
        "--",
        "global_cmd",
        "--global",
    ]
    proj_block = cc_data["projects"][proj_path]["mcpServers"]["proj_srv"]
    assert "mcp-integrity" in proj_block["command"]
    assert proj_block["args"] == [
        "run",
        "--name",
        "proj_srv",
        "--mode",
        "audit",
        "--",
        "proj_cmd",
        "--proj",
    ]

    # Uninstall
    rc_un = main(["uninstall"])
    assert rc_un == 0
    out_un, _ = capsys.readouterr()
    assert "unwrapped   vsc_srv" in out_un
    assert "unwrapped   global_srv" in out_un
    assert "unwrapped   proj_srv" in out_un

    # Verify restoration
    vsc_restored = json.loads(vscode_file.read_text(encoding="utf-8"))
    assert vsc_restored["servers"]["vsc_srv"] == {"command": "node", "args": ["index.js"]}

    cc_restored = json.loads(claude_file.read_text(encoding="utf-8"))
    assert cc_restored["mcpServers"]["global_srv"] == {"command": "global_cmd", "args": ["--global"]}
    assert cc_restored["projects"][proj_path]["mcpServers"]["proj_srv"] == {
        "command": "proj_cmd",
        "args": ["--proj"],
    }


def test_init_no_configs_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    fake_home = tmp_path / "empty_home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    # Also ensure CWD has no .cursor or .vscode
    empty_cwd = tmp_path / "empty_cwd"
    empty_cwd.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(empty_cwd)

    rc = main(["init"])
    assert rc == 1
    _, err = capsys.readouterr()
    assert "no client configs found. Looked in:" in err
    assert "Claude Desktop" in err
    assert "Claude Code" in err
    assert "Cursor" in err
    assert "Windsurf" in err
    assert "VS Code" in err


def test_cli_log_and_pin_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture):
    guard_home = tmp_path / "mcp_integrity_home"
    guard_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MCP_INTEGRITY_HOME", str(guard_home))

    ts = "2026-09-20T12:00:00+00:00"
    log_entry = json.dumps({
        "ts": ts,
        "server": "test_srv",
        "tool": "test_tool",
        "rule": "allow",
    })
    (guard_home / "audit.jsonl").write_text(log_entry + "\n", encoding="utf-8")

    rc = main(["log"])
    assert rc == 0
    out, _ = capsys.readouterr()
    assert f"{ts} test_srv test_tool allow" in out

    pins_dir = guard_home / "pins"
    pins_dir.mkdir(parents=True, exist_ok=True)
    (pins_dir / "test_srv.json").write_text(
        json.dumps({
            "tool_a": {"first_seen": "2026-09-20T11:00:00", "sha256": "h1"},
            "tool_b": {"first_seen": "2026-09-20T11:00:00", "sha256": "h2", "observed_sha256": "h3"},
        }),
        encoding="utf-8",
    )

    rc_pin = main(["pin", "--list"])
    assert rc_pin == 0
    out_pin, _ = capsys.readouterr()
    assert "test_srv   tool_a   2026-09-20T11:00:00   up to date" in out_pin
    assert "test_srv   tool_b   2026-09-20T11:00:00   changed (pending accept)" in out_pin
