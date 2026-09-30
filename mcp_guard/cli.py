from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Sequence

from mcp_guard import __version__
from mcp_guard.clients import (
    discover_configs,
    find_server_entries,
    format_display_path,
    get_known_client_locations,
    is_remote_server,
    is_wrapped_server,
    set_server_entry_mode,
    unwrap_server_entry,
    wrap_server_entry,
    write_json_atomic,
)
from mcp_guard.config import get_config_mode, get_guard_home, set_config_mode
from mcp_guard.guard import Guard, accept_pin, pin_key
from mcp_guard.proxy import run_proxy


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Transparent stdio MCP proxy and security guard",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. run
    run_parser = subparsers.add_parser("run", help="Run an MCP server through the proxy")
    run_parser.add_argument("--mode", choices=["audit", "enforce"], default="audit", help="Guard mode: audit (default) or enforce")
    run_parser.add_argument("--audit-log", metavar="PATH", default=None, help="Path to audit log file")
    run_parser.add_argument("--name", metavar="LABEL", default=None, help="Server label for audit log")
    run_parser.add_argument("--home", metavar="PATH", default=None, help="State directory (default: ~/.mcp-guard)")
    run_parser.add_argument("server_command", nargs=argparse.REMAINDER, help="Server command after --")

    # 2. init
    init_parser = subparsers.add_parser("init", help="Find client configs and protect MCP servers")
    init_parser.add_argument("--client", metavar="NAME", default=None, help="Filter client config by name")
    init_parser.add_argument("--mode", choices=["audit", "enforce"], default="audit", help="Protection mode: audit (default) or enforce")
    init_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 3. uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Restore client configs to original unwrapped state")
    uninstall_parser.add_argument("--client", metavar="NAME", default=None, help="Filter client config by name")
    uninstall_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 4. status
    status_parser = subparsers.add_parser("status", help="Show protection status, servers, and call summary")
    status_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 5. enforce
    enforce_parser = subparsers.add_parser("enforce", help="Switch wrapped servers to enforce mode")
    enforce_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 6. audit
    audit_parser = subparsers.add_parser("audit", help="Switch wrapped servers to audit mode")
    audit_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 7. log
    log_parser = subparsers.add_parser("log", help="Display audit log entries")
    log_parser.add_argument("--tail", type=int, metavar="N", default=None, help="Show last N log entries")
    log_parser.add_argument("--follow", action="store_true", help="Continuously poll for new entries")
    log_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    # 8. pin
    pin_parser = subparsers.add_parser("pin", help="Manage pinned tool hashes")
    pin_parser.add_argument("--accept", nargs=2, metavar=("SERVER", "TOOL"), help="Accept updated hash for a tool on a server")
    pin_parser.add_argument("--list", action="store_true", help="List pinned tools and change status")
    pin_parser.add_argument("--pins-dir", metavar="PATH", default=None, help="Path to pins directory")
    pin_parser.add_argument("--home", metavar="PATH", default=None, help="State directory")

    return parser.parse_args(argv)


def handle_run(args: argparse.Namespace) -> int:
    cmd = list(args.server_command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.stderr.write("mcp-guard: error: server command required after --\n")
        sys.stderr.flush()
        return 2

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # Server stderr -> our stderr unchanged
        )
    except Exception as exc:
        sys.stderr.write(f"mcp-guard: failed to spawn {cmd[0]}: {exc}\n")
        sys.stderr.flush()
        return 1

    label = args.name or Path(cmd[0]).name
    guard_home = get_guard_home(args.home)
    pins_path = guard_home / "pins" / f"{pin_key(label, cmd)}.json"
    audit_path = Path(args.audit_log) if args.audit_log else None
    guard = Guard(
        mode=args.mode,
        audit_path=audit_path,
        pins_path=pins_path,
        home=guard_home,
        server=label,
    )

    return run_proxy(proc, guard=guard)


def handle_init(args: argparse.Namespace) -> int:
    home = get_guard_home(args.home)
    discovered = discover_configs(client_filter=args.client)
    if not discovered:
        sys.stderr.write("mcp-guard: no client configs found. Looked in:\n")
        for client_name, path in get_known_client_locations():
            sys.stderr.write(f"  - {client_name}: {format_display_path(path)}\n")
        sys.stderr.flush()
        return 1

    # Detect mcp-guard path
    mcp_guard_which = shutil.which("mcp-guard")
    if mcp_guard_which:
        mcp_guard_cmd = os.path.abspath(mcp_guard_which)
    else:
        resolved_argv0 = Path(sys.argv[0]).resolve()
        if "mcp-guard" in resolved_argv0.name:
            mcp_guard_cmd = str(resolved_argv0)
        else:
            venv_script = Path(sys.prefix) / "bin" / "mcp-guard"
            if venv_script.exists():
                mcp_guard_cmd = str(venv_script.resolve())
            else:
                mcp_guard_cmd = str(resolved_argv0)

    print(f"using {mcp_guard_cmd}")

    mode = args.mode or "audit"
    total_protected = 0
    has_errors = False

    for client_name, config_path in discovered:
        try:
            content = config_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("config root must be a JSON object")
        except Exception as e:
            sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
            has_errors = True
            continue

        entries = find_server_entries(data, client_name, config_path)
        if not entries:
            continue

        bak_file = Path(f"{config_path}.mcp-guard.bak")
        modified = False

        print(f"{client_name}  {format_display_path(config_path)}")
        for entry in entries:
            if is_remote_server(entry.data):
                print(f"  skipped   {entry.name} (remote server)")
            elif is_wrapped_server(entry.data):
                print(f"  already wrapped   {entry.name}")
                total_protected += 1
            else:
                if not modified and not bak_file.exists():
                    shutil.copy2(config_path, bak_file)
                wrap_server_entry(entry.data, entry.name, mode, mcp_guard_cmd)
                modified = True
                total_protected += 1
                print(f"  wrapped   {entry.name}")

        if modified:
            try:
                write_json_atomic(config_path, data)
            except Exception as e:
                sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
                has_errors = True

    set_config_mode(mode, home=home)
    print(f"{total_protected} servers protected in {mode} mode. Restart your client. Then: mcp-guard status")
    return 1 if has_errors else 0


def handle_uninstall(args: argparse.Namespace) -> int:
    discovered = discover_configs(client_filter=getattr(args, "client", None))
    total_unwrapped = 0
    has_errors = False

    for client_name, config_path in discovered:
        try:
            content = config_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("config root must be a JSON object")
        except Exception as e:
            sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
            has_errors = True
            continue

        entries = find_server_entries(data, client_name, config_path)
        modified = False
        printed_header = False

        for entry in entries:
            if is_wrapped_server(entry.data):
                if not printed_header:
                    print(f"{client_name}  {format_display_path(config_path)}")
                    printed_header = True
                unwrap_server_entry(entry.data)
                modified = True
                total_unwrapped += 1
                print(f"  unwrapped   {entry.name}")

        if modified:
            try:
                write_json_atomic(config_path, data)
            except Exception as e:
                sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
                has_errors = True

    print(f"{total_unwrapped} servers restored to original configuration. Restart your client.")
    return 1 if has_errors else 0


def handle_mode_switch(new_mode: str, home_override: Path | str | None = None) -> int:
    home = get_guard_home(home_override)
    discovered = discover_configs()
    total_switched = 0
    has_errors = False

    for client_name, config_path in discovered:
        try:
            content = config_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("config root must be a JSON object")
        except Exception as e:
            sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
            has_errors = True
            continue

        entries = find_server_entries(data, client_name, config_path)
        modified = False
        for entry in entries:
            if is_wrapped_server(entry.data):
                set_server_entry_mode(entry.data, new_mode)
                modified = True
                total_switched += 1

        if modified:
            try:
                write_json_atomic(config_path, data)
            except Exception as e:
                sys.stderr.write(f"mcp-guard: error: {format_display_path(config_path)}: {e}\n")
                has_errors = True

    set_config_mode(new_mode, home=home)
    print(f"{total_switched} servers switched to {new_mode} mode. Restart your client.")
    return 1 if has_errors else 0


def handle_status(args: argparse.Namespace) -> int:
    home = get_guard_home(args.home)
    mode = get_config_mode(home=home)
    mode_desc = (
        "nothing is blocked; run 'mcp-guard enforce' to block"
        if mode == "audit"
        else "policy violations are blocked; run 'mcp-guard audit' to unblock"
    )
    print(f"mode: {mode} ({mode_desc})")

    # Servers list
    protected: list[str] = []
    unprotected: list[str] = []
    broken: list[str] = []
    remote: list[str] = []

    for client_name, c_path in discover_configs():
        try:
            d = json.loads(c_path.read_text(encoding="utf-8"))
            for entry in find_server_entries(d, client_name, c_path):
                label = f"{entry.client_name}/{entry.name}"
                if is_remote_server(entry.data):
                    remote.append(label)
                elif is_wrapped_server(entry.data):
                    cmd = str(entry.data.get("command", ""))
                    if shutil.which(cmd):
                        protected.append(label)
                    else:
                        broken.append(label)
                else:
                    unprotected.append(label)
        except Exception:
            pass

    total_servers = len(protected) + len(unprotected) + len(broken) + len(remote)
    if total_servers == 0:
        print("servers: none found")
    else:
        if protected:
            print(f"protected ({len(protected)}): {', '.join(sorted(protected))}")
        if unprotected:
            print(f"unprotected ({len(unprotected)}): {', '.join(sorted(unprotected))}   run 'mcp-guard init' to protect")
        if broken:
            print(f"broken ({len(broken)}): {', '.join(sorted(broken))}   launcher not found; re-run 'mcp-guard init'")
        if remote:
            print(f"remote, not covered ({len(remote)}): {', '.join(sorted(remote))}")

    audit_file = home / "audit.jsonl"
    if not audit_file.exists() or audit_file.stat().st_size == 0:
        print("no calls logged yet — is your client restarted?")
        return 0

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    if not lines or all(not line.strip() for line in lines):
        print("no calls logged yet — is your client restarted?")
        return 0

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    total_calls = 0
    would_block_count = 0
    suspicious_count = 0
    changed_count = 0

    would_blocks: dict[tuple[str, str, str], int] = {}
    suspicious_items: list[tuple[str, str, str]] = []
    changed_tools_set: set[tuple[str, str]] = set()

    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            continue

        ts_str = entry.get("ts")
        if ts_str:
            try:
                entry_dt = datetime.fromisoformat(ts_str)
                if entry_dt < cutoff:
                    continue
            except Exception:
                pass

        rule = entry.get("rule", "")
        server = entry.get("server", "unknown")
        tool = entry.get("tool", "unknown")
        allowed = entry.get("allowed", True)

        if rule == "suspicious_description":
            suspicious_count += 1
            for f in entry.get("findings", []):
                suspicious_items.append((server, tool, f))
        elif rule == "tool_changed":
            changed_count += 1
            changed_tools_set.add((server, tool))
        else:
            total_calls += 1
            if not allowed or rule in ("unknown_tool", "extra_argument"):
                would_block_count += 1
                key = (server, tool, rule)
                would_blocks[key] = would_blocks.get(key, 0) + 1

    print(
        f"last 24h: {total_calls} calls, {would_block_count} would-block, {suspicious_count} suspicious description, {changed_count} changed tools"
    )

    if would_blocks:
        print("would block:")
        for (srv, t, r), cnt in would_blocks.items():
            print(f"  {srv}   {t}   {r}   x{cnt}")

    if suspicious_items:
        print("suspicious:")
        for srv, t, f in suspicious_items:
            print(f"  {srv}   {t}   {f}")

    if changed_tools_set:
        print("changed tools:")
        for srv, t in sorted(changed_tools_set):
            print(f"  {srv}   {t}")
    else:
        print("changed tools: none")

    return 0


def handle_log(args: argparse.Namespace) -> int:
    home = get_guard_home(args.home)
    audit_file = home / "audit.jsonl"
    if not audit_file.exists():
        sys.stderr.write("mcp-guard: no audit log found\n")
        return 1

    def print_entry(line_str: str) -> None:
        try:
            entry = json.loads(line_str)
            ts = entry.get("ts", "")
            server = entry.get("server", "")
            tool = entry.get("tool", "")
            rule = entry.get("rule", "")
            print(f"{ts} {server} {tool} {rule}")
        except Exception:
            pass

    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    if args.tail is not None and args.tail > 0:
        lines = lines[-args.tail :]

    for l in lines:
        if l.strip():
            print_entry(l)

    if args.follow:
        with open(audit_file, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            try:
                while True:
                    line = f.readline()
                    if line:
                        print_entry(line.strip())
                    else:
                        time.sleep(0.5)
            except KeyboardInterrupt:
                return 0

    return 0


def handle_pin(args: argparse.Namespace) -> int:
    home = get_guard_home(args.home)
    pins_dir = Path(args.pins_dir) if args.pins_dir else home / "pins"

    if args.list:
        if not pins_dir.exists():
            print("no pinned tools found")
            return 0
        pin_files = sorted(pins_dir.glob("*.json"))
        if not pin_files:
            print("no pinned tools found")
            return 0
        for pf in pin_files:
            srv = pf.stem
            try:
                data = json.loads(pf.read_text(encoding="utf-8"))
            except Exception:
                continue
            for tool_name, info in sorted(data.items()):
                first_seen = info.get("first_seen", "")
                has_change = "observed_sha256" in info
                status_str = "changed (pending accept)" if has_change else "up to date"
                print(f"{srv}   {tool_name}   {first_seen}   {status_str}")
        return 0

    if args.accept:
        server_name, tool_name = args.accept
        ok = accept_pin(server_name, tool_name, pins_dir=pins_dir, home=home)
        if ok:
            sys.stderr.write(
                f"[mcp-guard] Accepted updated hash for tool '{tool_name}' on server '{server_name}'\n"
            )
            sys.stderr.flush()
            return 0
        else:
            sys.stderr.write(
                f"mcp-guard: failed to accept pin for tool '{tool_name}' on server '{server_name}' (no observed change or server pin missing)\n"
            )
            sys.stderr.flush()
            return 1

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.subcommand == "run":
        return handle_run(args)
    elif args.subcommand == "init":
        return handle_init(args)
    elif args.subcommand == "uninstall":
        return handle_uninstall(args)
    elif args.subcommand == "enforce":
        return handle_mode_switch("enforce", home_override=args.home)
    elif args.subcommand == "audit":
        return handle_mode_switch("audit", home_override=args.home)
    elif args.subcommand == "status":
        return handle_status(args)
    elif args.subcommand == "log":
        return handle_log(args)
    elif args.subcommand == "pin":
        return handle_pin(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
