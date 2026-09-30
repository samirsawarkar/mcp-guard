from __future__ import annotations

import json
import os
from pathlib import Path

from mcp_guard.clients import write_json_atomic


def get_guard_home(override: Path | str | None = None) -> Path:
    """Resolve the mcp-guard state directory.
    
    Precedence:
    1. Explicit override (e.g. CLI --home)
    2. MCP_GUARD_HOME environment variable
    3. Default ~/.mcp-guard
    """
    if override is not None:
        return Path(override)
    env_home = os.environ.get("MCP_GUARD_HOME")
    if env_home:
        return Path(env_home)
    return Path.home() / ".mcp-guard"


def get_config_mode(home: Path | str | None = None) -> str:
    """Read current guard mode from config.json, defaulting to 'audit'."""
    h = get_guard_home(home)
    cfg_file = h / "config.json"
    if cfg_file.exists():
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            return data.get("mode", "audit")
        except Exception:
            pass
    return "audit"


def set_config_mode(mode: str, home: Path | str | None = None) -> None:
    """Write guard mode to config.json."""
    h = get_guard_home(home)
    h.mkdir(parents=True, exist_ok=True)
    cfg_file = h / "config.json"
    cfg = {}
    if cfg_file.exists():
        try:
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    cfg["mode"] = mode
    write_json_atomic(cfg_file, cfg)
