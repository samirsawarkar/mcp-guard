from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import pytest

from mcp_integrity.cli import main
from mcp_integrity.clients import write_json_atomic
from mcp_integrity.guard import accept_pin


def test_write_json_atomic_roundtrip_permissions_and_symlink(tmp_path: Path):
    """(a) write_json_atomic: content round-trips, original mode bits preserved
    (chmod 600 before, still 600 after), symlinked config stays a symlink and
    the target is updated, no *.tmp files left in the directory.
    """
    # 1. Regular file with mode 0o600
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({"initial": 1}))
    os.chmod(cfg_file, 0o600)
    assert stat.S_IMODE(cfg_file.stat().st_mode) == 0o600

    new_data = {"key": "value", "list": [1, 2, 3]}
    write_json_atomic(cfg_file, new_data)

    # Content round-trips
    assert json.loads(cfg_file.read_text(encoding="utf-8")) == new_data
    # Mode bits preserved
    assert stat.S_IMODE(cfg_file.stat().st_mode) == 0o600
    # No *.tmp files
    tmp_files = [f for f in tmp_path.iterdir() if ".tmp" in f.name]
    assert tmp_files == []

    # 2. Symlinked config
    target_file = tmp_path / "real_target.json"
    target_file.write_text(json.dumps({"target_init": True}))
    os.chmod(target_file, 0o600)

    symlink_file = tmp_path / "symlink_config.json"
    symlink_file.symlink_to(target_file)
    assert symlink_file.is_symlink()

    symlink_data = {"updated_via_symlink": True, "count": 42}
    write_json_atomic(symlink_file, symlink_data)

    # Symlinked config stays a symlink
    assert symlink_file.is_symlink()
    assert symlink_file.resolve() == target_file.resolve()
    # Target is updated
    assert json.loads(target_file.read_text(encoding="utf-8")) == symlink_data
    assert json.loads(symlink_file.read_text(encoding="utf-8")) == symlink_data
    # Permissions preserved on target
    assert stat.S_IMODE(target_file.stat().st_mode) == 0o600
    # No *.tmp files left in directory
    tmp_files_all = [f for f in tmp_path.iterdir() if ".tmp" in f.name]
    assert tmp_files_all == []


def test_write_json_atomic_failure_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """(b) failure path: monkeypatch os.replace to raise OSError ->
    original file byte-identical, no temp file left, exception propagates.
    """
    test_dir = tmp_path / "atomic_failure_test"
    test_dir.mkdir(parents=True, exist_ok=True)
    p = test_dir / "protected.json"
    original_bytes = b'{\n  "safe": true\n}\n'
    p.write_bytes(original_bytes)

    def fail_replace(src, dst):
        raise OSError("simulated disk error during replace")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated disk error during replace"):
        write_json_atomic(p, {"safe": False, "corrupted": True})

    # Original file is byte-identical
    assert p.read_bytes() == original_bytes

    # No temp files left in directory
    leftover_files = list(test_dir.iterdir())
    assert leftover_files == [p]
    assert [f for f in leftover_files if ".tmp" in f.name] == []


def test_init_valid_and_invalid_json_configs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    """(c) init with one valid config + one config containing invalid JSON ->
    valid one is wrapped, invalid one is byte-identical, exit code 1, error line on stderr.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    # 1. Valid config: Claude Desktop
    claude_dir = fake_home / "Library" / "Application Support" / "Claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    valid_cfg = claude_dir / "claude_desktop_config.json"
    valid_cfg.write_text(
        json.dumps({
            "mcpServers": {
                "demo_srv": {
                    "command": "python",
                    "args": ["demo.py"],
                }
            }
        })
    )

    # 2. Invalid JSON config: Cursor
    cursor_dir = fake_home / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    invalid_cfg = cursor_dir / "mcp.json"
    invalid_bytes = b"INVALID JSON { NOT_PARSED"
    invalid_cfg.write_bytes(invalid_bytes)

    rc = main(["init"])
    assert rc == 1

    out, err = capsys.readouterr()
    # Error line printed on stderr
    assert "mcp-integrity: error:" in err
    assert "mcp.json" in err

    # Valid config was wrapped
    valid_data = json.loads(valid_cfg.read_text(encoding="utf-8"))
    srv = valid_data["mcpServers"]["demo_srv"]
    assert "mcp-integrity" in srv["command"]
    assert "wrapped   demo_srv" in out

    # Invalid config is byte-identical
    assert invalid_cfg.read_bytes() == invalid_bytes
    # No .bak created for invalid config
    assert not Path(f"{invalid_cfg}.mcp-integrity.bak").exists()


def test_uninstall_and_enforce_with_invalid_json_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
):
    """(d) uninstall and enforce with an invalid-JSON config -> exit code 1, file untouched."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))

    cursor_dir = fake_home / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    invalid_cfg = cursor_dir / "mcp.json"
    invalid_bytes = b"BROKEN JSON } } }"
    invalid_cfg.write_bytes(invalid_bytes)

    # 1. Test uninstall
    rc_un = main(["uninstall"])
    assert rc_un == 1
    assert invalid_cfg.read_bytes() == invalid_bytes
    _, err_un = capsys.readouterr()
    assert "mcp-integrity: error:" in err_un

    # 2. Test enforce
    rc_enf = main(["enforce"])
    assert rc_enf == 1
    assert invalid_cfg.read_bytes() == invalid_bytes
    _, err_enf = capsys.readouterr()
    assert "mcp-integrity: error:" in err_enf


def test_accept_pin_legitimate_double_dot_and_path_traversal(tmp_path: Path):
    """Pin file named 'a..b-abc123def456.json' with an observed_sha256 can be accepted;
    '../x' is still rejected.
    """
    pins_dir = tmp_path / "pins"
    pins_dir.mkdir(parents=True, exist_ok=True)

    # Legitimate pin key containing ".."
    pin_file = pins_dir / "a..b-abc123def456.json"
    pin_file.write_text(
        json.dumps({
            "target_tool": {
                "sha256": "old_hash_value",
                "observed_sha256": "new_hash_value",
                "observed_at": "2026-09-30T10:00:00Z",
            }
        })
    )

    # accept_pin should succeed for "a..b-abc123def456"
    ok = accept_pin("a..b-abc123def456", "target_tool", pins_dir=pins_dir)
    assert ok is True

    # Hash updated, observed fields removed
    updated_data = json.loads(pin_file.read_text(encoding="utf-8"))
    assert updated_data["target_tool"]["sha256"] == "new_hash_value"
    assert "observed_sha256" not in updated_data["target_tool"]
    assert "observed_at" not in updated_data["target_tool"]

    # Traversal attempt "../x" is rejected
    assert accept_pin("../x", "target_tool", pins_dir=pins_dir) is False

    # Traversal attempt ".." is rejected
    assert accept_pin("..", "target_tool", pins_dir=pins_dir) is False
