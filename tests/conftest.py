from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def isolate_mcp_guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Ensure no test ever writes to the real ~/.mcp-guard directory."""
    guard_home = tmp_path / "mcp_guard_home"
    guard_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MCP_GUARD_HOME", str(guard_home))
    return guard_home
