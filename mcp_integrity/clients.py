from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple


def write_json_atomic(path: Path | str, data: Any) -> None:
    """Write JSON data to path atomically using a temporary file.

    Preserves symlinks (writes to resolved target) and existing file permissions.
    """
    p = Path(path)
    content = json.dumps(data, indent=2) + "\n"
    target = p.resolve() if p.is_symlink() else p
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tf:
            tmp_path = Path(tf.name)
            tf.write(content)
            tf.flush()
            os.fsync(tf.fileno())

        if target.exists():
            mode = stat.S_IMODE(target.stat().st_mode)
            os.chmod(tmp_path, mode)

        os.replace(tmp_path, target)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


@dataclass
class ServerEntry:
    name: str
    client_name: str
    config_path: Path
    data: Dict[str, Any]
    parent: Dict[str, Any]


def get_known_client_locations(home: Path | str | None = None) -> List[Tuple[str, Path]]:
    user_home = Path.home() if home is None else Path(home)
    locs: List[Tuple[str, Path]] = []

    # 1. Claude Desktop
    if sys.platform == "darwin":
        locs.append((
            "Claude Desktop",
            user_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ))
        locs.append((
            "Claude Desktop",
            user_home / ".config" / "Claude" / "claude_desktop_config.json",
        ))
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        locs.append((
            "Claude Desktop",
            (Path(appdata) if appdata else user_home / "AppData" / "Roaming") / "Claude" / "claude_desktop_config.json",
        ))
    else:
        locs.append((
            "Claude Desktop",
            user_home / ".config" / "Claude" / "claude_desktop_config.json",
        ))
        locs.append((
            "Claude Desktop",
            user_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ))

    # 2. Claude Code
    locs.append(("Claude Code", user_home / ".claude.json"))

    # 3. Cursor
    locs.append(("Cursor", user_home / ".cursor" / "mcp.json"))
    locs.append(("Cursor", Path.cwd() / ".cursor" / "mcp.json"))

    # 4. Windsurf
    locs.append(("Windsurf", user_home / ".codeium" / "windsurf" / "mcp_config.json"))

    # 5. VS Code
    locs.append(("VS Code", user_home / ".vscode" / "mcp.json"))
    locs.append(("VS Code", Path.cwd() / ".vscode" / "mcp.json"))

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: List[Tuple[str, Path]] = []
    for client, p in locs:
        key = f"{client}:{p}"
        if key not in seen:
            seen.add(key)
            deduped.append((client, p))

    return deduped


def format_display_path(path: Path) -> str:
    user_home = Path.home()
    try:
        rel = path.resolve().relative_to(user_home.resolve())
        return f"~/{rel}"
    except Exception:
        pass
    try:
        rel = path.relative_to(user_home)
        return f"~/{rel}"
    except Exception:
        pass
    try:
        rel = path.resolve().relative_to(Path.cwd().resolve())
        return f"./{rel}"
    except Exception:
        pass
    return str(path)


def discover_configs(
    client_filter: Optional[str] = None,
    home: Path | str | None = None,
) -> List[Tuple[str, Path]]:
    """Return existing known client config files, filtered if requested."""
    all_locs = get_known_client_locations(home=home)
    results = []
    for client_name, path in all_locs:
        if client_filter:
            if client_filter.lower() not in client_name.lower():
                continue
        if path.exists() and path.is_file():
            results.append((client_name, path))
    return results


def find_server_entries(config_data: Dict[str, Any], client_name: str, config_path: Path) -> List[ServerEntry]:
    """Find all server definitions in a parsed JSON config."""
    entries: List[ServerEntry] = []

    # 1. Top-level 'mcpServers' (Claude Desktop, Claude Code, Cursor, Windsurf)
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        for name, data in config_data["mcpServers"].items():
            if isinstance(data, dict):
                entries.append(ServerEntry(name, client_name, config_path, data, config_data["mcpServers"]))

    # 2. Top-level 'servers' (VS Code)
    if "servers" in config_data and isinstance(config_data["servers"], dict):
        for name, data in config_data["servers"].items():
            if isinstance(data, dict):
                entries.append(ServerEntry(name, client_name, config_path, data, config_data["servers"]))

    # 3. Claude Code per-project 'projects'.<path>.'mcpServers'
    if "projects" in config_data and isinstance(config_data["projects"], dict):
        for proj_path, proj_obj in config_data["projects"].items():
            if isinstance(proj_obj, dict) and "mcpServers" in proj_obj and isinstance(proj_obj["mcpServers"], dict):
                for name, data in proj_obj["mcpServers"].items():
                    if isinstance(data, dict):
                        entries.append(ServerEntry(name, client_name, config_path, data, proj_obj["mcpServers"]))

    return entries


def is_remote_server(server_data: Dict[str, Any]) -> bool:
    if "command" not in server_data or not server_data["command"]:
        return True
    if "url" in server_data:
        return True
    if server_data.get("type") in ("http", "sse"):
        return True
    return False


def is_wrapped_server(server_data: Dict[str, Any]) -> bool:
    cmd = str(server_data.get("command", ""))
    args = server_data.get("args")
    if not isinstance(args, list):
        return False
    is_mcp_integrity_cmd = (cmd == "mcp-integrity" or Path(cmd).name == "mcp-integrity")
    return is_mcp_integrity_cmd and ("run" in args and "--" in args)


def wrap_server_entry(
    server_data: Dict[str, Any],
    server_name: str,
    mode: str,
    mcp_integrity_cmd: str,
) -> bool:
    if is_remote_server(server_data) or is_wrapped_server(server_data):
        return False

    orig_cmd = server_data["command"]
    orig_args = server_data.get("args")
    if not isinstance(orig_args, list):
        orig_args = []

    server_data["command"] = mcp_integrity_cmd
    server_data["args"] = [
        "run",
        "--name",
        server_name,
        "--mode",
        mode,
        "--",
        orig_cmd,
        *orig_args,
    ]
    return True


def unwrap_server_entry(server_data: Dict[str, Any]) -> bool:
    if not is_wrapped_server(server_data):
        return False

    args = server_data.get("args", [])
    try:
        dash_idx = args.index("--")
    except ValueError:
        return False

    if dash_idx + 1 >= len(args):
        return False

    orig_cmd = args[dash_idx + 1]
    orig_args = args[dash_idx + 2 :]
    server_data["command"] = orig_cmd
    server_data["args"] = orig_args
    return True


def set_server_entry_mode(server_data: Dict[str, Any], new_mode: str) -> bool:
    if not is_wrapped_server(server_data):
        return False

    args = server_data.get("args", [])
    if "--mode" in args:
        idx = args.index("--mode")
        if idx + 1 < len(args):
            args[idx + 1] = new_mode
            return True

    dash_idx = args.index("--")
    args.insert(dash_idx, new_mode)
    args.insert(dash_idx, "--mode")
    return True
