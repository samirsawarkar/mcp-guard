from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, List, Set, Tuple

from mcp_guard.scan import scan_manifest


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str
    tool: str
    argument_keys: list[str]


QUARANTINE_FINDINGS: frozenset[str] = frozenset({
    "hidden_instruction",
    "exfiltration_target",
    "sensitive_path",
    "invisible_unicode",
})


from mcp_guard.clients import write_json_atomic
from mcp_guard.config import get_guard_home


def _sanitize_label(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", label).lstrip(".")[:64]
    return safe or "server"


def pin_key(label: str, server_command: list[str]) -> str:
    safe = _sanitize_label(label)
    h = hashlib.sha256(json.dumps([label, *server_command]).encode("utf-8")).hexdigest()[:12]
    return f"{safe}-{h}"


def accept_pin(
    server: str,
    tool: str,
    pins_dir: Path | str | None = None,
    home: Path | str | None = None,
) -> bool:
    """Accept the latest observed hash for a changed tool."""
    if "/" in server or "\\" in server:
        return False
    p_dir = Path(pins_dir) if pins_dir else get_guard_home(home) / "pins"
    pins_file = p_dir / f"{server}.json"
    try:
        if pins_file.resolve().parent != p_dir.resolve():
            return False
    except Exception:
        return False
    if not pins_file.exists():
        return False
    try:
        pins = json.loads(pins_file.read_text(encoding="utf-8"))
    except Exception:
        return False
    if tool not in pins:
        return False
    tool_entry = pins[tool]
    if "observed_sha256" in tool_entry:
        tool_entry["sha256"] = tool_entry.pop("observed_sha256")
        tool_entry.pop("observed_at", None)
        write_json_atomic(pins_file, pins)
        return True
    return False


def trust_pin(
    server: str,
    tool: str,
    pins_dir: Path | str | None = None,
    home: Path | str | None = None,
) -> bool:
    """Store trusted_sha256 for a tool to bypass quarantine."""
    if "/" in server or "\\" in server:
        return False
    p_dir = Path(pins_dir) if pins_dir else get_guard_home(home) / "pins"
    pins_file = p_dir / f"{server}.json"
    try:
        if pins_file.resolve().parent != p_dir.resolve():
            return False
    except Exception:
        return False
    if not pins_file.exists():
        return False
    try:
        pins = json.loads(pins_file.read_text(encoding="utf-8"))
    except Exception:
        return False
    if tool not in pins:
        return False
    tool_entry = pins[tool]
    target_hash = tool_entry.get("observed_sha256") or tool_entry.get("sha256")
    if not target_hash:
        return False
    tool_entry["trusted_sha256"] = target_hash
    write_json_atomic(pins_file, pins)
    return True


class Guard:
    def __init__(
        self,
        mode: str = "audit",
        audit_path: Path | str | None = None,
        pins_path: Path | str | None = None,
        home: Path | str | None = None,
        server: str = "default",
        reply: Callable[[bytes], None] | None = None,
    ) -> None:
        if mode not in ("audit", "enforce"):
            raise ValueError(f"Invalid mode: {mode}. Must be 'audit' or 'enforce'.")
        self.mode = mode
        self.home = get_guard_home(home)
        if audit_path is None:
            self.audit_path = self.home / "audit.jsonl"
        else:
            self.audit_path = Path(audit_path)

        self.server = server
        if pins_path is None:
            self.pins_path = self.home / "pins" / f"{_sanitize_label(self.server)}.json"
        else:
            self.pins_path = Path(pins_path)

        self.reply = reply

        self.tools: Dict[str, Dict[str, Any]] = {}
        self.has_manifest: bool = False
        self._pending_cursorless_tools_list_ids: Set[Any] = set()
        self._pending_paginated_tools_list_ids: Set[Any] = set()
        # tool name -> (rule, findings) last logged, so later pages don't re-log unchanged findings
        self._logged_findings: Dict[str, Tuple[str, frozenset]] = {}

    def _should_log_findings(self, tool_name: str, rule: str, findings: List[str]) -> bool:
        key = (rule, frozenset(findings))
        if self._logged_findings.get(tool_name) == key:
            return False
        self._logged_findings[tool_name] = key
        return True

    def _load_pins(self) -> Dict[str, Any]:
        if self.pins_path.exists():
            try:
                return json.loads(self.pins_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_pins(self, pins: Dict[str, Any]) -> None:
        write_json_atomic(self.pins_path, pins)

    def evaluate(self, tool_name: str, arguments: dict) -> Decision:
        arg_keys = sorted(list(arguments.keys()))

        # Rule 1: unknown_tool (or no_manifest if tools/list not yet seen)
        if not self.has_manifest:
            return Decision(
                allowed=False,
                rule="no_manifest",
                reason="no tools/list seen yet; client must list tools before calling",
                tool=tool_name,
                argument_keys=arg_keys,
            )

        if tool_name not in self.tools:
            return Decision(
                allowed=False,
                rule="unknown_tool",
                reason=f"Tool '{tool_name}' not in listed tools",
                tool=tool_name,
                argument_keys=arg_keys,
            )

        # Rug-pull detection: tool_changed check
        tool_info = self.tools[tool_name]
        current_hash = tool_info.get("sha256")
        pins = self._load_pins()
        if tool_name in pins and current_hash:
            stored_hash = pins[tool_name].get("sha256")
            if stored_hash and stored_hash != current_hash:
                first_seen = pins[tool_name].get("first_seen", "unknown")
                reason = f"tool {tool_name} description/schema changed since {first_seen}"
                if self.mode == "enforce":
                    return Decision(
                        allowed=False,
                        rule="tool_changed",
                        reason=reason,
                        tool=tool_name,
                        argument_keys=arg_keys,
                    )

        # Rule 2: extra_argument
        declared_args: Set[str] = tool_info["declared_args"]
        additional_properties: bool = tool_info["additional_properties"]

        if not additional_properties:
            for arg_name in arg_keys:
                if arg_name not in declared_args:
                    return Decision(
                        allowed=False,
                        rule="extra_argument",
                        reason=f"Argument '{arg_name}' not declared for tool '{tool_name}'",
                        tool=tool_name,
                        argument_keys=arg_keys,
                    )

        return Decision(
            allowed=True,
            rule="allow",
            reason=f"Tool call '{tool_name}' permitted",
            tool=tool_name,
            argument_keys=arg_keys,
        )

    def _log_audit(self, decision: Decision, extra: Dict[str, Any] | None = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "server": self.server,
            "tool": decision.tool,
            "rule": decision.rule,
            "allowed": decision.allowed,
            "mode": self.mode,
            "reason": decision.reason,
            "argument_keys": decision.argument_keys,
        }
        if extra:
            entry.update(extra)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def client_line(self, line: bytes) -> bytes | None:
        try:
            data = json.loads(line.decode("utf-8"))
        except Exception:
            return line

        if not isinstance(data, dict):
            return line

        method = data.get("method")
        req_id = data.get("id")

        if method == "tools/list":
            if req_id is not None:
                params = data.get("params") or {}
                cursor = params.get("cursor") if isinstance(params, dict) else None
                if cursor:
                    self._pending_paginated_tools_list_ids.add(req_id)
                else:
                    self._pending_cursorless_tools_list_ids.add(req_id)
            return line

        if method == "tools/call":
            params = data.get("params")
            if not isinstance(params, dict):
                params = {}
            tool_name = params.get("name")
            if not isinstance(tool_name, str):
                tool_name = "unknown"
            arguments = params.get("arguments")
            if not isinstance(arguments, dict):
                arguments = {}

            decision = self.evaluate(tool_name, arguments)
            self._log_audit(decision)

            if not decision.allowed:
                if self.mode == "enforce":
                    sys.stderr.write(
                        f"[mcp-guard] BLOCKED tool={decision.tool} rule={decision.rule} {decision.reason}\n"
                    )
                    sys.stderr.flush()
                    if self.reply is not None:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32001,
                                "message": f"mcp-guard blocked: {decision.rule}: {decision.reason}",
                            },
                        }
                        self.reply(json.dumps(err_resp).encode("utf-8") + b"\n")
                    return None
                else:  # audit mode
                    sys.stderr.write(
                        f"[mcp-guard] WOULD BLOCK tool={decision.tool} rule={decision.rule} {decision.reason}\n"
                    )
                    sys.stderr.flush()
                    return line

        return line

    def server_line(self, line: bytes) -> bytes | None:
        try:
            data = json.loads(line.decode("utf-8"))
        except Exception:
            return line

        if not isinstance(data, dict):
            return line

        method = data.get("method")
        if method == "notifications/tools/list_changed":
            self.tools.clear()
            self._logged_findings.clear()
            self.has_manifest = False
            return line

        req_id = data.get("id")
        if req_id is not None:
            is_cursorless = req_id in self._pending_cursorless_tools_list_ids
            is_paginated = req_id in self._pending_paginated_tools_list_ids
            if is_cursorless or is_paginated:
                if is_cursorless:
                    self._pending_cursorless_tools_list_ids.remove(req_id)
                    self.tools.clear()
                    self._logged_findings.clear()
                else:
                    self._pending_paginated_tools_list_ids.remove(req_id)

                result = data.get("result")
                if isinstance(result, dict) and "tools" in result:
                    tools_list = result.get("tools")
                    if isinstance(tools_list, list):
                        pins = self._load_pins()
                        pins_updated = False

                        for tool in tools_list:
                            if isinstance(tool, dict) and "name" in tool:
                                name = tool["name"]
                                desc = tool.get("description", "")
                                input_schema = tool.get("inputSchema")
                                if isinstance(input_schema, dict):
                                    props = input_schema.get("properties")
                                    if isinstance(props, dict):
                                        declared_args = set(props.keys())
                                    else:
                                        declared_args = set()
                                    additional_properties = bool(
                                        input_schema.get("additionalProperties", False)
                                    )
                                else:
                                    declared_args = set()
                                    additional_properties = False

                                # Canonical sha256 for rug-pull detection
                                canonical_obj = {
                                    "name": name,
                                    "description": desc,
                                    "inputSchema": input_schema if isinstance(input_schema, dict) else {},
                                }
                                canonical_bytes = json.dumps(canonical_obj, sort_keys=True).encode("utf-8")
                                tool_hash = hashlib.sha256(canonical_bytes).hexdigest()

                                self.tools[name] = {
                                    "name": name,
                                    "description": desc,
                                    "declared_args": declared_args,
                                    "additional_properties": additional_properties,
                                    "sha256": tool_hash,
                                }

                                # Check rug-pull persistence
                                if name not in pins:
                                    pins[name] = {
                                        "sha256": tool_hash,
                                        "first_seen": datetime.now(timezone.utc).isoformat(),
                                    }
                                    pins_updated = True
                                else:
                                    stored_hash = pins[name].get("sha256")
                                    first_seen = pins[name].get("first_seen", "unknown")
                                    if stored_hash and stored_hash != tool_hash:
                                        pins[name]["observed_sha256"] = tool_hash
                                        pins[name]["observed_at"] = datetime.now(timezone.utc).isoformat()
                                        pins_updated = True
                                        reason = f"tool {name} description/schema changed since {first_seen}"
                                        sys.stderr.write(f"[mcp-guard] CHANGED tool={name} {reason}\n")
                                        sys.stderr.flush()
                                        self._log_audit(
                                            Decision(
                                                allowed=True,
                                                rule="tool_changed",
                                                reason=reason,
                                                tool=name,
                                                argument_keys=[],
                                            )
                                        )

                        if pins_updated:
                            self._save_pins(pins)

                        # Run description scanner on tools
                        manifest_descriptions = {
                            t_name: t_val["description"]
                            for t_name, t_val in self.tools.items()
                        }
                        # Scan the cumulative manifest: a later page can add findings
                        # (cross_tool_reference) to a tool listed on an earlier page.
                        findings_by_tool = scan_manifest(manifest_descriptions)
                        if self.mode == "audit":
                            for tool_name, findings in findings_by_tool.items():
                                if findings and self._should_log_findings(tool_name, "suspicious_description", findings):
                                    findings_str = ",".join(findings)
                                    sys.stderr.write(
                                        f"[mcp-guard] SUSPICIOUS tool={tool_name} findings={findings_str}\n"
                                    )
                                    sys.stderr.flush()
                                    self._log_audit(
                                        Decision(
                                            allowed=True,
                                            rule="suspicious_description",
                                            reason=f"Suspicious description findings: {findings_str}",
                                            tool=tool_name,
                                            argument_keys=[],
                                        ),
                                        extra={"findings": findings},
                                    )
                        else:  # enforce mode
                            quarantined_tools: Set[str] = set()
                            for t_name, findings in findings_by_tool.items():
                                if findings:
                                    tool_pin = pins.get(t_name, {})
                                    trusted_hash = tool_pin.get("trusted_sha256")
                                    current_hash = self.tools.get(t_name, {}).get("sha256")
                                    is_trusted = bool(
                                        trusted_hash and current_hash and trusted_hash == current_hash
                                    )
                                    should_quarantine = bool(set(findings) & QUARANTINE_FINDINGS) and not is_trusted
                                    if should_quarantine:
                                        quarantined_tools.add(t_name)
                                        self.tools.pop(t_name, None)
                                        if self._should_log_findings(t_name, "quarantined", findings):
                                            findings_str = ",".join(findings)
                                            sys.stderr.write(
                                                f"[mcp-guard] QUARANTINED tool={t_name} findings={findings_str}\n"
                                            )
                                            sys.stderr.flush()
                                            self._log_audit(
                                                Decision(
                                                    allowed=False,
                                                    rule="quarantined",
                                                    reason=f"Suspicious description findings: {findings_str}",
                                                    tool=t_name,
                                                    argument_keys=[],
                                                ),
                                                extra={"findings": findings},
                                            )
                                    elif self._should_log_findings(t_name, "suspicious_description", findings):
                                        findings_str = ",".join(findings)
                                        sys.stderr.write(
                                            f"[mcp-guard] SUSPICIOUS tool={t_name} findings={findings_str}\n"
                                        )
                                        sys.stderr.flush()
                                        self._log_audit(
                                            Decision(
                                                allowed=True,
                                                rule="suspicious_description",
                                                reason=f"Suspicious description findings: {findings_str}",
                                                tool=t_name,
                                                argument_keys=[],
                                            ),
                                            extra={"findings": findings},
                                        )

                            if quarantined_tools:
                                result["tools"] = [
                                    t
                                    for t in tools_list
                                    if not (isinstance(t, dict) and t.get("name") in quarantined_tools)
                                ]
                                data["result"] = result
                                self.has_manifest = True
                                return (json.dumps(data) + "\n").encode("utf-8")

                    self.has_manifest = True

        return line
