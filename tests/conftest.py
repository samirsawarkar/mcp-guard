from __future__ import annotations

from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def isolate_mcp_integrity_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Ensure no test ever writes to the real ~/.mcp-integrity directory."""
    guard_home = tmp_path / "mcp_integrity_home"
    guard_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MCP_INTEGRITY_HOME", str(guard_home))
    return guard_home
