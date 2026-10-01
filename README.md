# mcp-integrity

[![CI](https://github.com/samirsawarkar/mcp-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/samirsawarkar/mcp-guard/actions)
[![PyPI](https://img.shields.io/pypi/v/mcp-integrity.svg)](https://pypi.org/project/mcp-integrity/)

mcp-integrity is a local integrity monitor for stdio MCP servers. It sits between your AI client and your servers, logs every tool call (argument names only), scans tool descriptions for poisoning, pins tool definitions to catch silent changes, and in enforce mode blocks calls that break the rules.

## 30-second install

Requires Python 3.10 or newer and an existing stdio MCP server configured in your client. This release is tested on macOS and Linux. Windows has not been validated.

```bash
pip install mcp-integrity
mcp-integrity init
```

If your Python installation refuses package installation into the system environment, use a virtual environment:

```bash
python3 -m venv ~/.venvs/mcp-integrity
~/.venvs/mcp-integrity/bin/pip install mcp-integrity
~/.venvs/mcp-integrity/bin/mcp-integrity init
```

Keep that environment installed: the client configuration uses its absolute launcher path. Use the same launcher for `status`, `enforce`, and other commands.

Restart your MCP client (for example, Claude Desktop or Cursor).

```bash
mcp-integrity status
```

```text
mode: audit (nothing is blocked; run 'mcp-integrity enforce' to block)
protected (3): Claude Desktop/filesystem, Claude Desktop/github, Claude Desktop/postgres
last 24h: 142 calls, 1 would-block, 1 suspicious description, 0 changed tools, 0 quarantined
would block:
  github   delete_repo   unknown_tool   x1
suspicious:
  filesystem   read_file   hidden_instruction
changed tools: none
```

## What it checks

| Rule | What it catches | Blocks in enforce? |
| --- | --- | --- |
| `no_manifest` | A tool call arrives before the client has listed tools (or right after the server said its tool list changed) | Yes |
| `unknown_tool` | Client calls a tool not declared in the server's tools/list manifest | Yes |
| `extra_argument` | Client sends arguments not defined in the tool's inputSchema | Yes |
| `tool_changed` | Server silently altered a tool's schema or description after first run (rug-pull) | Yes |
| `suspicious_description` | Tool description matches any scanner finding: `hidden_instruction`, `exfiltration_target`, `sensitive_path`, `invisible_unicode`, `cross_tool_reference` | No. Warns in both modes; the tool still reaches the model. In enforce mode a tool that gets quarantined is logged as `quarantined` instead |
| `quarantined` | Enforce mode only. Tool description has a high-confidence finding: `hidden_instruction`, `exfiltration_target`, `sensitive_path` or `invisible_unicode` | Yes. The tool is removed from tools/list so the model never sees it |

`cross_tool_reference` is warning-only. It never removes a tool, in either mode.

## Audit mode vs enforce mode

Default is audit: nothing changes for you, you just get a log. Run `mcp-integrity enforce` to block rule violations with an MCP error response. In enforce mode, tools with a high-confidence scanner finding are also quarantined: removed from tools/list so the model never sees them. Use `mcp-integrity pin --trust <server> <tool>` for a clean tool that got removed. Run `mcp-integrity audit` to go back. Restart your client after either mode change so its server processes use the new mode.

## What it does NOT do

- Does not see your chat messages, so it cannot check whether a tool call's arguments match what you asked (that check exists in the underlying research but needs the user turn; coming as a library API for people who run their own agent loop).
- Does not inspect tool RESULTS.
- Does not protect remote (HTTP/SSE) servers yet.
- The heuristic scanner can miss poisoned tools (about 30% on MCPTox) and can remove clean ones (0.8% of clean tools on MCPTox). Use `mcp-integrity pin --trust <server> <tool>` for a clean tool it removed.

## Measured on MCPTox

We ran mcp-integrity's own rules over MCPTox, a public tool-poisoning benchmark (1,312 poisoned tools on 45 real MCP servers, 10,227 recorded model responses labelled by the benchmark authors). $0, no model calls. Script: `bench/mcptox_bench.py`, results: `bench/results_mcptox.json`.

| Check | Result | 95% CI |
| --- | --- | --- |
| Scanner: poisoned descriptions flagged | 70.4% (924 / 1,312) | 67.9 to 72.8% |
| Scanner, per description: clean descriptions flagged | 0.9% (3 / 327) | 0.3 to 2.7% |
| Warnings in the proxy (incl. cross-tool): clean tools flagged | 4.4% (16 / 362), 6 of 45 servers | 2.7 to 7.1% |
| Quarantine: clean tools removed | 0.8% (3 / 362), 3 of 45 servers | 0.3 to 2.4% |
| Quarantine: poisoned tools removed | 70.4% (924 / 1,312) | 67.9 to 72.8% |
| Quarantine: successful attacks whose poisoned tool is removed | 66.9% (1,167 / 1,745), upper-bound estimate from a $0 replay, not a live rerun | 64.6 to 69.0% |
| Call rules: successful attacks blocked | 3.8% (62 / 1,653) | 2.9 to 4.8% |
| Call rules: harmless responses blocked | 3.5% (184 / 5,188) | 3.1 to 4.1% |
| Pinning: attacks detected | 0% (0 / 1,312) | n/a |

What this means:
- Quarantine is the part that acts against this attack. In enforce mode it removes the poisoned tool in 70.4% of MCPTox instances, so the model never sees it.
- The 66.9% is an upper bound. It assumes that removing the poisoned tool removes the attack. It comes from replaying recorded responses, not from rerunning the models.
- The call rules barely help here (3.8% of successful attacks blocked): MCPTox attacks call real, listed tools with valid arguments.
- Pinning catches a tool that changes after you first saw it. Every MCPTox attack adds a new tool instead, so pinning sees none of them.

Reproduce:
```bash
python bench/mcptox_bench.py
```
Needs the MCPTox data file from inspect-evals-mcptox (default path ~/Library/Caches/inspect_evals_mcptox/response_all.json, override with --data).

## Where things live

- `~/.mcp-integrity/audit.jsonl`: Audit log containing argument NAMES only, never values.
- `~/.mcp-integrity/pins/`: Pinned tool schema and description hashes per server to detect rug-pulls.
- `<file>.mcp-integrity.bak`: Backup created next to each client config file on first wrap.

`mcp-integrity uninstall` restores everything.

## All commands

- `mcp-integrity init`: Finds client configs and wraps stdio MCP servers in audit mode.
- `mcp-integrity status`: Shows protection mode, which servers are protected, unprotected, broken, or remote, 24h call counts, would-blocks, and warnings.
- `mcp-integrity log`: Displays audit log entries in `<time> <server> <tool> <rule>` format; supports `--tail N` and `--follow`.
- `mcp-integrity enforce`: Switches all wrapped servers to enforce mode.
- `mcp-integrity audit`: Switches all wrapped servers to audit mode.
- `mcp-integrity pin --list` / `--accept` / `--trust`: Lists pinned tool statuses, accepts updated hashes after a legitimate tool change, or trusts a tool to bypass quarantine.
- `mcp-integrity uninstall`: Restores all wrapped client configs to their original unwrapped commands.
- `mcp-integrity run`: Wraps a single server by hand (`mcp-integrity run -- <server_command>`).

For `pin --trust` and `pin --accept`, use the exact server key printed by `mcp-integrity pin --list` (for example, `filesystem-012345abcdef`), plus the tool name. Restart the server or client after trusting or accepting a tool so it refreshes tools/list. Trust applies only to the specific tool hash; a later description or schema change still requires review.

## Why

Built from FAULTLINE's P8 study (https://github.com/samirsawarkar/faultline-ai-reliability). There, a client-side contract cut MCPTox attack success from 30% to 7% across six models, mostly through a rule that checks each argument against the user's own message. A proxy never sees that message, so mcp-integrity ships the parts that do not need it. The numbers above are mcp-integrity's own, not P8's.

## License

MIT
