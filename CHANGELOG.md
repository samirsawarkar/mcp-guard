# Changelog

## 0.1.0 - 2026-10-01

- Stdio proxy between an MCP client and a server. Logs every tool call with argument names only, never values.
- Audit mode (default) logs; enforce mode blocks. In enforce mode a tool call is refused until the server's tools/list has been seen (fails closed).
- Pinning: tool schemas and descriptions are hashed on first run, and a later change is flagged as `tool_changed`. Pin files are kept inside the guard home (`~/.mcp-integrity/pins/`).
- Description scanner. Every finding is logged as a warning. In enforce mode, tools with a high-confidence finding (`hidden_instruction`, `exfiltration_target`, `sensitive_path`, `invisible_unicode`) are quarantined: removed from tools/list. `cross_tool_reference` is warning-only.
- `mcp-integrity pin --trust <server> <tool>` to keep a quarantined tool, and `pin --accept <server> <tool>` to accept a legitimate tool change.
- Config and pin files are written atomically.
- `mcp-integrity status` reports what is actually protected, unprotected, broken or remote, plus 24h counts.
- MCPTox numbers for the scanner, quarantine, call rules and pinning: see [Measured on MCPTox](README.md#measured-on-mcptox).

- Paginated tools/list scans log newly discovered cross-tool warnings from earlier pages without duplicating unchanged findings.
- Setup instructions cover Python requirements, virtual environments, client restarts and exact pin server keys.
