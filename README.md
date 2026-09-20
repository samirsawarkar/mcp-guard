# mcp-guard

[![CI](https://github.com/samirsawarkar/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/samirsawarkar/mcp-guard/actions)
[![PyPI](https://img.shields.io/pypi/v/mcp-guard.svg)](https://pypi.org/project/mcp-guard/)

A local firewall for MCP tool calls. Sits between your AI client and your MCP servers; logs every tool call, flags poisoned tool descriptions, and (when you turn it on) blocks calls that break the rules.

## 30-second install

```bash
pip install mcp-guard
mcp-guard init
```

Restart Claude Desktop / Cursor / whatever you use.

```bash
mcp-guard status
```

```text
mode: audit (nothing is blocked; run 'mcp-guard enforce' to block)
servers: filesystem, github, postgres
last 24h: 142 calls, 0 would-block, 1 suspicious description, 0 changed tools
would block:
  github   delete_repo   unknown_tool   x3
suspicious:
  filesystem   read_file   hidden_instruction
changed tools: none
```

## What it checks

| Rule | What it catches | Blocks in enforce? |
| --- | --- | --- |
| `unknown_tool` | Client calls a tool not declared in the server's tools/list manifest | Yes |
| `extra_argument` | Client sends arguments not defined in the tool's inputSchema | Yes |
| `tool_changed` | Server silently altered a tool's schema or description after first run (rug-pull) | Yes |
| `suspicious_description` | Tool description contains prompt injection heuristics (finding labels: `hidden_instruction`, `exfiltration_target`, `sensitive_path`, `invisible_unicode`, `cross_tool_reference`) | No (warn only) |

## Audit mode vs enforce mode

Default is audit: nothing changes for you, you just get a log. Run `mcp-guard enforce` to block rule violations with an MCP error response. Run `mcp-guard audit` to go back.

## What it does NOT do

- Does not see your chat messages, so it cannot check whether a tool call's arguments match what you asked (that check exists in the underlying research but needs the user turn — coming as a library API for people who run their own agent loop).
- Does not inspect tool RESULTS.
- Does not protect remote (HTTP/SSE) servers yet.
- Heuristic scanner can miss things and can false-positive; that's why it only warns.

## Where things live

- `~/.mcp-guard/audit.jsonl`: Audit log containing argument NAMES only, never values.
- `~/.mcp-guard/pins/`: Pinned tool schema and description hashes per server to detect rug-pulls.
- `<file>.mcp-guard.bak`: Backup created next to each client config file on first wrap.

`mcp-guard uninstall` restores everything.

## All commands

- `mcp-guard init`: Finds client configs and wraps stdio MCP servers in audit mode.
- `mcp-guard status`: Displays protection mode, configured servers, 24h call counts, would-blocks, and warnings.
- `mcp-guard log`: Displays audit log entries in `<time> <server> <tool> <rule>` format; supports `--tail N` and `--follow`.
- `mcp-guard enforce`: Switches all wrapped servers to enforce mode.
- `mcp-guard audit`: Switches all wrapped servers to audit mode.
- `mcp-guard pin --list` / `--accept`: Lists pinned tool statuses or accepts updated hashes after a legitimate tool change.
- `mcp-guard uninstall`: Restores all wrapped client configs to their original unwrapped commands.
- `mcp-guard run`: Wraps a single server by hand (`mcp-guard run -- <server_command>`).

## Why

Built from FAULTLINE's P8 study on the MCPTox benchmark, where a client-side provenance contract cut pooled attack success from 30% to 7% across six models. See https://github.com/samirsawarkar/faultline-ai-reliability. The proxy implements the subset of that contract that does not need the user's message.

## License

MIT
