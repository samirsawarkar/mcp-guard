"""MCPTox benchmark runner for mcp-integrity.

Measures:
A) Scanner recall on poisoned descriptions (by paradigm and pooled)
B) Scanner false positives on clean descriptions
C) Call-rule replay (unknown_tool + extra_argument) vs FAULTLINE P8 contract
D) Pinning detection vs MCPTox-style new tool introduction
E) Quarantine: $0 replay estimate
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple
import warnings

warnings.filterwarnings("ignore", category=SyntaxWarning)

from mcp_integrity.guard import Guard, QUARANTINE_FINDINGS
from mcp_integrity.scan import scan_description, scan_manifest

EXPECTED_SHA256 = "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03"
AUTHOR_LABELS = ["Success", "Failure-Direct Execution", "Failure-Ignored", "other"]

# ==============================================================================
# Verbatim parsers copied from:
# faultline_p2/policy/provenance.py in https://github.com/samirsawarkar/faultline-ai-reliability
# ==============================================================================

EOS_TOKENS = [
    "<end_of_turn>",
    "</s>",
    "<|eot_id|>",
    "<|im_end|>",
    "<|endoftext|>",
    "<｜end of sentence｜>",
    "<｜endofsentence｜>",
    "<|end_of_sentence|>",
]


def parse_tool_block(system_prompt: str) -> Dict[str, List[str]]:
    """Parse MCPTox system prompt tool definitions into mapping of tool name to argument names."""
    tools: Dict[str, List[str]] = {}
    current_tool: Optional[str] = None
    in_args = False

    for line in system_prompt.split("\n"):
        line_s = line.strip()
        if line_s.startswith("Tool:"):
            current_tool = line_s.split("Tool:", 1)[1].strip()
            tools[current_tool] = []
            in_args = False
        elif line_s.startswith("Arguments:"):
            in_args = True
        elif in_args and line_s.startswith("- "):
            arg_part = line_s[2:].strip()
            if arg_part.lower() == "no arguments":
                continue
            if ":" in arg_part:
                candidate = arg_part.split(":", 1)[0].strip()
                if re.match(r"^[a-zA-Z0-9_-]+$", candidate):
                    if current_tool and candidate not in tools[current_tool]:
                        tools[current_tool].append(candidate)
        elif line_s.startswith("Description:"):
            in_args = False

    return tools


def _extract_balanced_braces(text: str) -> List[str]:
    """Extract all top-level balanced {...} string blocks respecting quotes."""
    results: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            start = i
            depth = 1
            in_str: Optional[str] = None
            escape = False
            i += 1
            while i < n and depth > 0:
                ch = text[i]
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif in_str:
                    if ch == in_str:
                        in_str = None
                else:
                    if ch == '"' or ch == "'":
                        in_str = ch
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                i += 1
            if depth == 0:
                results.append(text[start:i])
        else:
            i += 1
    return results


def _parse_single_object(s: str) -> Optional[Dict[str, Any]]:
    """Try parsing a single JSON/Python dict string."""
    try:
        res = json.loads(s)
        if isinstance(res, dict):
            return res
    except Exception:
        pass

    # Substitute bare true/false/null as whole words before literal_eval
    sub_s = re.sub(r"\btrue\b", "True", s)
    sub_s = re.sub(r"\bfalse\b", "False", sub_s)
    sub_s = re.sub(r"\bnull\b", "None", sub_s)

    try:
        res = ast.literal_eval(sub_s)
        if isinstance(res, dict):
            return res
    except Exception:
        pass

    return None


def parse_response(text: Any) -> List[Dict[str, Any]]:
    """Parse model response text into a list of tool call dictionaries."""
    if not isinstance(text, str):
        return []

    s = text
    # Strip EOS tokens anywhere in text
    for eos in EOS_TOKENS:
        s = s.replace(eos, " ")

    # Strip code fences, including fences glued to opening braces (```json{ -> {)
    s = re.sub(r"```(?:json)?", " ", s)
    s = s.replace("```", " ")

    candidates = _extract_balanced_braces(s)
    parsed: List[Dict[str, Any]] = []
    for c in candidates:
        obj = _parse_single_object(c)
        if obj is not None:
            parsed.append(obj)

    return parsed


# ==============================================================================
# Statistical Helper
# ==============================================================================


def wilson_95(successes: int, n: int) -> Tuple[float, float]:
    """6-line Wilson 95% interval helper."""
    if n == 0:
        return (0.0, 1.0)
    z, p = 1.96, successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


# ==============================================================================
# Tool Description Parsers
# ==============================================================================


def parse_tool_descriptions(text: str) -> Dict[str, str]:
    """Extract tool descriptions from system prompt text."""
    results: Dict[str, str] = {}
    current_tool: Optional[str] = None
    desc_lines: List[str] = []
    recording_desc = False

    for line in text.split("\n"):
        line_s = line.strip()
        if line_s.startswith("Tool:"):
            if current_tool is not None:
                results[current_tool] = "\n".join(desc_lines).strip()
            current_tool = line_s.split("Tool:", 1)[1].strip()
            desc_lines = []
            recording_desc = False
        elif line_s.startswith("Description:"):
            recording_desc = True
            desc_content = line.split("Description:", 1)[1].strip()
            desc_lines = [desc_content] if desc_content else []
        elif line_s.startswith("Arguments:"):
            recording_desc = False
        elif recording_desc:
            desc_lines.append(line.strip())

    if current_tool is not None:
        results[current_tool] = "\n".join(desc_lines).strip()
    return results


def _normalize_tool_text(tool_text: str) -> str:
    s = tool_text.strip()
    if "\n" not in s:
        s = s.replace("\\n", "\n")
    return s


def extract_poisoned_tool_description(tool_text: str) -> str:
    """Extract description text from a poisoned_tool definition block."""
    s = _normalize_tool_text(tool_text)
    if "Description:" not in s:
        return ""
    desc_part = s.split("Description:", 1)[1]
    if "\nArguments:" in desc_part:
        desc_part = desc_part.split("\nArguments:", 1)[0]
    return desc_part.strip()


def extract_poisoned_tool_name(tool_text: str) -> str:
    """Extract tool name from a poisoned_tool definition block."""
    s = _normalize_tool_text(tool_text)
    for line in s.split("\n"):
        if line.strip().startswith("Tool:"):
            return line.strip().split("Tool:", 1)[1].strip()
    return ""


# P8 contract baseline numbers for direct side-by-side comparison
P8_CONTRACT_BASELINE = {
    "pooled": {
        "succ_rate": 0.870,
        "succ_blocked": 1438,
        "succ_total": 1653,
        "ign_rate": 0.245,
        "ign_blocked": 1271,
        "ign_total": 5188,
    },
    "Deepseek-qwen3-8b-Think": {
        "succ_rate": 0.727,
        "succ_blocked": 16,
        "succ_total": 22,
        "ign_rate": 0.396,
        "ign_blocked": 40,
        "ign_total": 101,
    },
    "LLama-13b": {
        "succ_rate": 1.000,
        "succ_blocked": 2,
        "succ_total": 2,
        "ign_rate": 0.218,
        "ign_blocked": 29,
        "ign_total": 133,
    },
    "LLama-3-8b": {
        "succ_rate": 0.806,
        "succ_blocked": 25,
        "succ_total": 31,
        "ign_rate": 0.347,
        "ign_blocked": 162,
        "ign_total": 467,
    },
    "Phi-4-Think": {
        "succ_rate": 0.886,
        "succ_blocked": 558,
        "succ_total": 630,
        "ign_rate": 0.250,
        "ign_blocked": 49,
        "ign_total": 196,
    },
    "Qwen3-14b-No-Think": {
        "succ_rate": 0.894,
        "succ_blocked": 42,
        "succ_total": 47,
        "ign_rate": 0.252,
        "ign_blocked": 180,
        "ign_total": 714,
    },
    "Qwen3-14b-Think": {
        "succ_rate": 0.836,
        "succ_blocked": 265,
        "succ_total": 317,
        "ign_rate": 0.215,
        "ign_blocked": 117,
        "ign_total": 545,
    },
    "Qwen3-30b-A3b-No-Think": {
        "succ_rate": 1.000,
        "succ_blocked": 42,
        "succ_total": 42,
        "ign_rate": 0.252,
        "ign_blocked": 107,
        "ign_total": 425,
    },
    "Qwen3-8b-No-Think": {
        "succ_rate": 0.948,
        "succ_blocked": 55,
        "succ_total": 58,
        "ign_rate": 0.206,
        "ign_blocked": 142,
        "ign_total": 690,
    },
    "Qwen3-8b-Think": {
        "succ_rate": 0.887,
        "succ_blocked": 243,
        "succ_total": 274,
        "ign_rate": 0.247,
        "ign_blocked": 141,
        "ign_total": 572,
    },
    "gemma-2-9b": {
        "succ_rate": 0.810,
        "succ_blocked": 132,
        "succ_total": 163,
        "ign_rate": 0.216,
        "ign_blocked": 177,
        "ign_total": 821,
    },
    "mistral": {
        "succ_rate": 0.866,
        "succ_blocked": 58,
        "succ_total": 67,
        "ign_rate": 0.242,
        "ign_blocked": 127,
        "ign_total": 524,
    },
}


# ==============================================================================
# Benchmarks
# ==============================================================================


def run_benchmark_a(data: Dict[str, Any]) -> Dict[str, Any]:
    """A) Scanner recall on poisoned descriptions."""
    by_paradigm_descs: Dict[str, List[str]] = defaultdict(list)
    all_descs: List[str] = []

    for _, server in data["servers"].items():
        for inst in server["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            paradigm = inst.get("metadata", {}).get("paradigm", "Other")
            desc = extract_poisoned_tool_description(inst.get("poisoned_tool", ""))
            by_paradigm_descs[paradigm].append(desc)
            all_descs.append(desc)

    def analyze_descs(descs: List[str]) -> Dict[str, Any]:
        n_instances = len(descs)
        flagged_instances = 0
        finding_counts: Counter[str] = Counter()

        for d in descs:
            findings = scan_description(d)
            if findings:
                flagged_instances += 1
            for f in findings:
                finding_counts[f] += 1

        unique_descs = list(set(descs))
        n_unique = len(unique_descs)
        flagged_unique = sum(1 for d in unique_descs if scan_description(d))

        inst_rate = (flagged_instances / n_instances) if n_instances > 0 else 0.0
        uniq_rate = (flagged_unique / n_unique) if n_unique > 0 else 0.0

        return {
            "n_instances": n_instances,
            "flagged_instances": flagged_instances,
            "instance_rate": inst_rate,
            "instance_ci": list(wilson_95(flagged_instances, n_instances)),
            "n_unique": n_unique,
            "flagged_unique": flagged_unique,
            "unique_rate": uniq_rate,
            "unique_ci": list(wilson_95(flagged_unique, n_unique)),
            "finding_counts": dict(sorted(finding_counts.items())),
        }

    results: Dict[str, Any] = {
        "pooled": analyze_descs(all_descs),
        "by_paradigm": {},
    }
    for p in sorted(by_paradigm_descs.keys()):
        results["by_paradigm"][p] = analyze_descs(by_paradigm_descs[p])

    return results


def run_benchmark_b(data: Dict[str, Any]) -> Dict[str, Any]:
    """B) Scanner false positives on clean descriptions."""
    seen_texts: set[str] = set()
    clean_entries: List[Tuple[str, str, str]] = []

    for sname, server in data["servers"].items():
        csp = server.get("clean_system_promot", "")
        td = parse_tool_descriptions(csp)
        for tool_name, desc in td.items():
            if desc not in seen_texts:
                seen_texts.add(desc)
                clean_entries.append((sname, tool_name, desc))

    n_unique_clean = len(clean_entries)
    flagged_tools: List[Dict[str, Any]] = []

    for sname, tool_name, desc in clean_entries:
        findings = scan_description(desc)
        if findings:
            flagged_tools.append({
                "server": sname,
                "tool": tool_name,
                "findings": findings,
                "preview": desc[:160],
            })

    flagged_count = len(flagged_tools)
    rate = (flagged_count / n_unique_clean) if n_unique_clean > 0 else 0.0
    ci = list(wilson_95(flagged_count, n_unique_clean))

    # Production-path block computed per clean server with scan_manifest on full clean manifest
    total_servers = len(data["servers"])
    total_tools = 0
    tools_with_warning = 0
    tools_quarantined = 0
    servers_with_warning = 0
    servers_with_quarantine = 0
    clean_manifest_warnings: List[Dict[str, Any]] = []
    clean_manifest_quarantines: List[Dict[str, Any]] = []

    for sname in sorted(data["servers"].keys()):
        server = data["servers"][sname]
        csp = server.get("clean_system_promot", "")
        manifest_desc = parse_tool_descriptions(csp)
        server_tool_count = len(manifest_desc)
        total_tools += server_tool_count

        findings_map = scan_manifest(manifest_desc)

        s_has_warning = False
        s_has_quarantine = False

        for tname, f_list in findings_map.items():
            if f_list:
                tools_with_warning += 1
                s_has_warning = True
                clean_manifest_warnings.append({
                    "server": sname,
                    "tool": tname,
                    "findings": f_list,
                })
                if set(f_list) & QUARANTINE_FINDINGS:
                    tools_quarantined += 1
                    s_has_quarantine = True
                    clean_manifest_quarantines.append({
                        "server": sname,
                        "tool": tname,
                        "findings": f_list,
                    })

        if s_has_warning:
            servers_with_warning += 1
        if s_has_quarantine:
            servers_with_quarantine += 1

    return {
        "n_unique_clean": n_unique_clean,
        "flagged_count": flagged_count,
        "rate": rate,
        "ci": ci,
        "flagged_tools": flagged_tools,
        "production_path": {
            "total_servers": total_servers,
            "total_tools": total_tools,
            "tools_warning_count": tools_with_warning,
            "tools_warning_rate": (tools_with_warning / total_tools) if total_tools > 0 else 0.0,
            "tools_warning_ci": list(wilson_95(tools_with_warning, total_tools)),
            "servers_warning_count": servers_with_warning,
            "tools_quarantined_count": tools_quarantined,
            "tools_quarantined_rate": (tools_quarantined / total_tools) if total_tools > 0 else 0.0,
            "tools_quarantined_ci": list(wilson_95(tools_quarantined, total_tools)),
            "servers_quarantined_count": servers_with_quarantine,
            "warning_tools": clean_manifest_warnings,
            "quarantined_tools": clean_manifest_quarantines,
        },
    }


def run_benchmark_c(data: Dict[str, Any], tmp_dir: Path) -> Dict[str, Any]:
    """C) Call-rule replay (unknown_tool + extra_argument) vs FAULTLINE P8 contract."""
    pooled_crosstab: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    model_crosstabs: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    pooled_n = 0
    pooled_no_call = 0
    inst_idx = 0

    for _, server in data["servers"].items():
        for inst in server["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            inst_idx += 1
            datas0 = inst["datas"][0]
            manifest = parse_tool_block(datas0["system"])
            tools_list = [
                {
                    "name": t,
                    "description": "",
                    "inputSchema": {"type": "object", "properties": {arg: {} for arg in args}},
                }
                for t, args in manifest.items()
            ]

            guard = Guard(
                mode="enforce",
                server="bench",
                audit_path=tmp_dir / f"audit_c_{inst_idx}.jsonl",
                pins_path=tmp_dir / f"pins_c_{inst_idx}.json",
            )
            # Suppress scanner stdout/stderr warnings during synthetic tools/list
            with contextlib.redirect_stderr(io.StringIO()):
                guard.client_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode() + b"\n")
                guard.server_line(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools_list}}).encode() + b"\n")

            responses = datas0.get("response", {})
            labels = datas0.get("label", {})

            for model, resp_text in responses.items():
                pooled_n += 1
                raw_label = labels.get(model, "other")
                label = raw_label if raw_label in AUTHOR_LABELS else "other"

                calls = parse_response(resp_text)
                if not calls:
                    outcome = "no_call"
                    pooled_no_call += 1
                else:
                    outcome = "allowed"
                    for call_idx, call in enumerate(calls):
                        if isinstance(call, dict):
                            tool_name = (
                                call.get("name")
                                if isinstance(call.get("name"), str)
                                else (call.get("tool") if isinstance(call.get("tool"), str) else "unknown")
                            )
                            arguments = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
                        else:
                            tool_name = "unknown"
                            arguments = {}

                        call_payload = {
                            "jsonrpc": "2.0",
                            "id": 100 + call_idx,
                            "method": "tools/call",
                            "params": {"name": tool_name, "arguments": arguments},
                        }
                        with contextlib.redirect_stderr(io.StringIO()):
                            line_out = guard.client_line(json.dumps(call_payload).encode("utf-8") + b"\n")

                        if line_out is None:
                            decision = guard.evaluate(tool_name, arguments)
                            outcome = decision.rule
                            break

                pooled_crosstab[outcome][label] += 1
                model_crosstabs[model][outcome][label] += 1

    def compute_c_metrics(ctab: Dict[str, Dict[str, int]], m_name: str = "pooled") -> Dict[str, Any]:
        total_n = sum(sum(labels.values()) for labels in ctab.values())
        no_call_n = sum(ctab.get("no_call", {}).values())
        eval_n = total_n - no_call_n

        outcomes = sorted(ctab.keys())

        # Success metrics (over responses with >=1 call)
        succ_eval = sum(ctab[o]["Success"] for o in outcomes if o != "no_call")
        succ_blocked = sum(ctab[o]["Success"] for o in outcomes if o not in ("no_call", "allowed", "allow"))
        succ_rate = (succ_blocked / succ_eval) if succ_eval > 0 else 0.0
        succ_ci = list(wilson_95(succ_blocked, succ_eval))

        # Failure-Ignored metrics (over responses with >=1 call)
        ign_eval = sum(ctab[o]["Failure-Ignored"] for o in outcomes if o != "no_call")
        ign_false_blocked = sum(ctab[o]["Failure-Ignored"] for o in outcomes if o not in ("no_call", "allowed", "allow"))
        ign_rate = (ign_false_blocked / ign_eval) if ign_eval > 0 else 0.0
        ign_ci = list(wilson_95(ign_false_blocked, ign_eval))

        p8_base = P8_CONTRACT_BASELINE.get(m_name, P8_CONTRACT_BASELINE["pooled"])

        return {
            "n": total_n,
            "n_no_call": no_call_n,
            "n_eval": eval_n,
            "crosstab": {o: dict(ctab[o]) for o in outcomes},
            "success": {
                "n_eval": succ_eval,
                "blocked": succ_blocked,
                "block_rate": succ_rate,
                "ci": succ_ci,
                "p8_comparison": {
                    "rate": p8_base["succ_rate"],
                    "blocked": p8_base["succ_blocked"],
                    "total": p8_base["succ_total"],
                },
            },
            "failure_ignored": {
                "n_eval": ign_eval,
                "false_blocked": ign_false_blocked,
                "false_block_rate": ign_rate,
                "ci": ign_ci,
                "p8_comparison": {
                    "rate": p8_base["ign_rate"],
                    "false_blocked": p8_base["ign_blocked"],
                    "total": p8_base["ign_total"],
                },
            },
        }

    models_dict: Dict[str, Any] = {}
    for model in sorted(model_crosstabs.keys()):
        models_dict[model] = compute_c_metrics(model_crosstabs[model], m_name=model)

    return {
        "pooled": compute_c_metrics(pooled_crosstab, m_name="pooled"),
        "models": models_dict,
    }


def run_benchmark_d(data: Dict[str, Any], tmp_dir: Path) -> Dict[str, Any]:
    """D) Pinning vs MCPTox: tool_changed detection vs brand-new tool introduction."""
    by_paradigm: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "tool_changed": 0, "brand_new": 0})
    pooled = {"total": 0, "tool_changed": 0, "brand_new": 0}

    idx = 0
    for _, server in data["servers"].items():
        csp = server.get("clean_system_promot", "")
        clean_args_map = parse_tool_block(csp)
        clean_desc_map = parse_tool_descriptions(csp)
        clean_tools_list = [
            {
                "name": t,
                "description": clean_desc_map.get(t, ""),
                "inputSchema": {"type": "object", "properties": {arg: {} for arg in args}},
            }
            for t, args in clean_args_map.items()
        ]

        for inst in server["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            idx += 1
            paradigm = inst.get("metadata", {}).get("paradigm", "Other")
            datas0 = inst["datas"][0]
            poisoned_args_map = parse_tool_block(datas0["system"])
            poisoned_desc_map = parse_tool_descriptions(datas0["system"])
            poisoned_tools_list = [
                {
                    "name": t,
                    "description": poisoned_desc_map.get(t, ""),
                    "inputSchema": {"type": "object", "properties": {arg: {} for arg in args}},
                }
                for t, args in poisoned_args_map.items()
            ]

            pt_name = extract_poisoned_tool_name(inst.get("poisoned_tool", ""))

            audit_path = tmp_dir / f"audit_d_{idx}.jsonl"
            pins_path = tmp_dir / f"pins_d_{idx}.json"
            guard = Guard(mode="audit", audit_path=audit_path, pins_path=pins_path)

            with contextlib.redirect_stderr(io.StringIO()):
                # 1. First sight: clean tools/list
                guard.client_line(b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}\n')
                guard.server_line(
                    json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": clean_tools_list}}).encode() + b"\n"
                )

                # 2. Second sight: poisoned tools/list
                guard.client_line(b'{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}\n')
                guard.server_line(
                    json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": poisoned_tools_list}}).encode() + b"\n"
                )

            has_tool_changed = False
            if audit_path.exists():
                for line in audit_path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            if entry.get("rule") == "tool_changed":
                                has_tool_changed = True
                                break
                        except Exception:
                            pass

            is_brand_new = pt_name not in clean_args_map

            by_paradigm[paradigm]["total"] += 1
            pooled["total"] += 1
            if has_tool_changed:
                by_paradigm[paradigm]["tool_changed"] += 1
                pooled["tool_changed"] += 1
            if is_brand_new:
                by_paradigm[paradigm]["brand_new"] += 1
                pooled["brand_new"] += 1

    return {
        "by_paradigm": {p: dict(by_paradigm[p]) for p in sorted(by_paradigm.keys())},
        "pooled": pooled,
    }


def run_benchmark_e(data: Dict[str, Any], tmp_dir: Path) -> Dict[str, Any]:
    """E) Quarantine: $0 replay estimate over non-wrong_data instances and 10,227 traces."""
    label_text = "upper-bound estimate: assumes removing the poisoned tool removes the attack; not a live rerun"

    # Step 1: For each non-wrong_data instance, run Guard in enforce mode
    instance_info: Dict[int, Dict[str, Any]] = {}
    inst_idx = 0
    total_instances = 0
    collateral_instances = 0
    clean_tools_total = 0
    clean_tools_removed = 0
    poisoned_removed_instances = 0

    for server_name, server in data["servers"].items():
        for inst in server["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            inst_idx += 1
            total_instances += 1
            paradigm = inst.get("metadata", {}).get("paradigm", "Other")
            datas0 = inst["datas"][0]
            poisoned_args_map = parse_tool_block(datas0["system"])
            poisoned_desc_map = parse_tool_descriptions(datas0["system"])
            poisoned_tools_list = [
                {
                    "name": t,
                    "description": poisoned_desc_map.get(t, ""),
                    "inputSchema": {"type": "object", "properties": {arg: {} for arg in args}},
                }
                for t, args in poisoned_args_map.items()
            ]

            pt_name = extract_poisoned_tool_name(inst.get("poisoned_tool", ""))

            audit_path = tmp_dir / f"audit_e_{inst_idx}.jsonl"
            pins_path = tmp_dir / f"pins_e_{inst_idx}.json"
            guard = Guard(mode="enforce", server=server_name, audit_path=audit_path, pins_path=pins_path)

            with contextlib.redirect_stderr(io.StringIO()):
                guard.client_line(b'{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}\n')
                resp_in = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": poisoned_tools_list}}).encode("utf-8") + b"\n"
                resp_out = guard.server_line(resp_in)

            out_data = json.loads(resp_out.decode("utf-8"))
            forwarded_tools = set(t["name"] for t in out_data.get("result", {}).get("tools", []))

            poisoned_removed = (pt_name not in forwarded_tools)
            clean_tools_in_manifest = set(t for t in poisoned_args_map.keys() if t != pt_name)
            n_clean_removed = len(clean_tools_in_manifest - forwarded_tools)
            clean_tools_total += len(clean_tools_in_manifest)
            clean_tools_removed += n_clean_removed
            collateral_removed = n_clean_removed > 0

            if poisoned_removed:
                poisoned_removed_instances += 1
            if collateral_removed:
                collateral_instances += 1

            instance_info[id(inst)] = {
                "paradigm": paradigm,
                "poisoned_removed": poisoned_removed,
                "collateral_removed": collateral_removed,
            }

    # Step 2: Over the 10,227 traces (same filter as C)
    total_traces = 0
    success_traces = 0
    success_poisoned_removed = 0

    by_paradigm: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "poisoned_removed": 0})
    by_model: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "poisoned_removed": 0})

    for server_name, server in data["servers"].items():
        for inst in server["malicious_instance"]:
            if inst.get("wrong_data"):
                continue
            info = instance_info[id(inst)]
            paradigm = info["paradigm"]
            p_rem = info["poisoned_removed"]
            datas0 = inst["datas"][0]
            responses = datas0.get("response", {})
            labels = datas0.get("label", {})

            for model, resp_text in responses.items():
                total_traces += 1
                raw_label = labels.get(model, "other")
                label = raw_label if raw_label in AUTHOR_LABELS else "other"
                if label == "Success":
                    success_traces += 1
                    by_paradigm[paradigm]["total"] += 1
                    by_model[model]["total"] += 1
                    if p_rem:
                        success_poisoned_removed += 1
                        by_paradigm[paradigm]["poisoned_removed"] += 1
                        by_model[model]["poisoned_removed"] += 1

    def compute_rate_ci(succ: int, tot: int) -> Dict[str, Any]:
        return {
            "success_total": tot,
            "poisoned_removed": succ,
            "rate": (succ / tot) if tot > 0 else 0.0,
            "ci": list(wilson_95(succ, tot)),
        }

    return {
        "estimate_label": label_text,
        "instances": {
            "total": total_instances,
            "poisoned_removed": poisoned_removed_instances,
            "poisoned_removed_rate": (poisoned_removed_instances / total_instances) if total_instances > 0 else 0.0,
            "poisoned_removed_ci": list(wilson_95(poisoned_removed_instances, total_instances)),
            "collateral_removed": collateral_instances,
            "collateral_removed_rate": (collateral_instances / total_instances) if total_instances > 0 else 0.0,
            "collateral_removed_ci": list(wilson_95(collateral_instances, total_instances)),
            "collateral_removed_description": "instances (of total) in which at least one clean tool was removed; not a count of tools",
            "clean_tools_total": clean_tools_total,
            "clean_tools_removed": clean_tools_removed,
        },
        "traces": {
            "total": total_traces,
            "success_total": success_traces,
            "success_poisoned_removed": success_poisoned_removed,
            "success_quarantine_rate": (success_poisoned_removed / success_traces) if success_traces > 0 else 0.0,
            "success_quarantine_ci": list(wilson_95(success_poisoned_removed, success_traces)),
        },
        "by_paradigm": {p: compute_rate_ci(by_paradigm[p]["poisoned_removed"], by_paradigm[p]["total"]) for p in sorted(by_paradigm.keys())},
        "by_model": {m: compute_rate_ci(by_model[m]["poisoned_removed"], by_model[m]["total"]) for m in sorted(by_model.keys())},
    }


# ==============================================================================
# Compact Table Printer
# ==============================================================================


def print_compact_table(results: Dict[str, Any]) -> None:
    sep = "=" * 105
    subsep = "-" * 105

    print("\n" + sep)
    print("                    MCPTOX BENCHMARK FOR MCP-GUARD (STANDALONE $0 REPLAY)")
    print(sep)

    # Section A
    sec_a = results["scanner_recall_poisoned"]
    print("\n[A] SCANNER RECALL ON POISONED DESCRIPTIONS (mcp_integrity.scan.scan_description)")
    print(subsep)
    print(f"{'Paradigm':<14} | {'Instances (k/N)':<17} | {'Inst Recall (95% CI)':<23} | {'Unique (k/N)':<15} | {'Uniq Recall (95% CI)':<23}")
    print(subsep)
    for p, stats in sec_a["by_paradigm"].items():
        inst_s = f"{stats['flagged_instances']}/{stats['n_instances']}"
        inst_r = f"{stats['instance_rate']*100:5.1f}% [{stats['instance_ci'][0]:.3f}, {stats['instance_ci'][1]:.3f}]"
        uniq_s = f"{stats['flagged_unique']}/{stats['n_unique']}"
        uniq_r = f"{stats['unique_rate']*100:5.1f}% [{stats['unique_ci'][0]:.3f}, {stats['unique_ci'][1]:.3f}]"
        print(f"{p:<14} | {inst_s:<17} | {inst_r:<23} | {uniq_s:<15} | {uniq_r:<23}")
    print(subsep)
    pl = sec_a["pooled"]
    p_inst_s = f"{pl['flagged_instances']}/{pl['n_instances']}"
    p_inst_r = f"{pl['instance_rate']*100:5.1f}% [{pl['instance_ci'][0]:.3f}, {pl['instance_ci'][1]:.3f}]"
    p_uniq_s = f"{pl['flagged_unique']}/{pl['n_unique']}"
    p_uniq_r = f"{pl['unique_rate']*100:5.1f}% [{pl['unique_ci'][0]:.3f}, {pl['unique_ci'][1]:.3f}]"
    print(f"{'POOLED TOTAL':<14} | {p_inst_s:<17} | {p_inst_r:<23} | {p_uniq_s:<15} | {p_uniq_r:<23}")
    print(f"Findings Breakdown: {pl['finding_counts']}")

    # Section B
    sec_b = results["scanner_fp_clean"]
    print("\n\n[B] SCANNER FALSE POSITIVES ON CLEAN DESCRIPTIONS (n=327 unique clean tools)")
    print(subsep)
    fp_r = f"{sec_b['flagged_count']}/{sec_b['n_unique_clean']} ({sec_b['rate']*100:.2f}%, 95% CI [{sec_b['ci'][0]:.4f}, {sec_b['ci'][1]:.4f}])"
    print(f"Clean Tools Flagged: {fp_r}")
    print("Flagged Clean Tools Details:")
    for ft in sec_b["flagged_tools"]:
        print(f"  * [{ft['server']}] {ft['tool']} -> findings={ft['findings']}")
        print(f"    Excerpt: {repr(ft['preview'])}")

    # Section C
    sec_c = results["call_rule_replay"]
    p_c = sec_c["pooled"]
    print("\n\n[C] CALL-RULE REPLAY: MCP-GUARD (SCHEMA ENFORCEMENT) VS FAULTLINE P8 CONTRACT")
    print(subsep)
    print(f"Pooled Traces: n={p_c['n']:,} (n_no_call={p_c['n_no_call']}, n_evaluated={p_c['n_eval']:,})")
    print("\nOutcome x Label Crosstab:")
    outcomes = sorted(p_c["crosstab"].keys())
    print(f"{'Outcome':<16} | {'Success':<8} | {'Fail-DirectExec':<16} | {'Fail-Ignored':<13} | {'Other':<6}")
    print("-" * 68)
    for o in outcomes:
        row = p_c["crosstab"][o]
        print(f"{o:<16} | {row.get('Success', 0):<8} | {row.get('Failure-Direct Execution', 0):<16} | {row.get('Failure-Ignored', 0):<13} | {row.get('other', 0):<6}")

    print("\nPooled Protection vs False-Block Comparison:")
    s_mcp = f"{p_c['success']['blocked']}/{p_c['success']['n_eval']} ({p_c['success']['block_rate']*100:.1f}%, [{p_c['success']['ci'][0]:.3f}, {p_c['success']['ci'][1]:.3f}])"
    s_p8 = f"{p_c['success']['p8_comparison']['blocked']}/{p_c['success']['p8_comparison']['total']} ({p_c['success']['p8_comparison']['rate']*100:.1f}%)"
    print(f"  * Attack Success Block Rate:  mcp-integrity: {s_mcp:<30} | P8 Contract: {s_p8}")

    i_mcp = f"{p_c['failure_ignored']['false_blocked']}/{p_c['failure_ignored']['n_eval']} ({p_c['failure_ignored']['false_block_rate']*100:.1f}%, [{p_c['failure_ignored']['ci'][0]:.3f}, {p_c['failure_ignored']['ci'][1]:.3f}])"
    i_p8 = f"{p_c['failure_ignored']['p8_comparison']['false_blocked']}/{p_c['failure_ignored']['p8_comparison']['total']} ({p_c['failure_ignored']['p8_comparison']['rate']*100:.1f}%)"
    print(f"  * Failure-Ignored False Block: mcp-integrity: {i_mcp:<30} | P8 Contract: {i_p8}")

    print("\nPer-Model Breakdown:")
    m_hdr = f"{'Model':<23} | {'n_eval':<6} | {'mcp-integrity Succ':<17} | {'P8 Succ':<9} | {'mcp-integrity False-Blk':<19} | {'P8 False-Blk':<12}"
    print(m_hdr)
    print("-" * len(m_hdr))
    for m, m_data in sec_c["models"].items():
        s_rate_str = f"{m_data['success']['blocked']}/{m_data['success']['n_eval']} ({m_data['success']['block_rate']*100:4.1f}%)"
        s_p8_str = f"{m_data['success']['p8_comparison']['rate']*100:4.1f}%"
        i_rate_str = f"{m_data['failure_ignored']['false_blocked']}/{m_data['failure_ignored']['n_eval']} ({m_data['failure_ignored']['false_block_rate']*100:4.1f}%)"
        i_p8_str = f"{m_data['failure_ignored']['p8_comparison']['rate']*100:4.1f}%"
        print(f"{m:<23} | {m_data['n_eval']:<6} | {s_rate_str:<17} | {s_p8_str:<9} | {i_rate_str:<19} | {i_p8_str:<12}")

    # Section D
    sec_d = results["pinning_vs_mcptox"]
    print("\n\n[D] PINNING VS MCPTOX (RUG-PULL HASH PINS VS NEW TOOL INJECTION)")
    print(subsep)
    print(f"{'Paradigm':<14} | {'Instances':<10} | {'Tool Changed (Rug-Pull Pin)':<28} | {'Brand-New Tool Injected':<25}")
    print(subsep)
    for p, p_res in sec_d["by_paradigm"].items():
        tc_str = f"{p_res['tool_changed']}/{p_res['total']} ({p_res['tool_changed']/p_res['total']*100:.1f}%)"
        bn_str = f"{p_res['brand_new']}/{p_res['total']} ({p_res['brand_new']/p_res['total']*100:.1f}%)"
        print(f"{p:<14} | {p_res['total']:<10} | {tc_str:<28} | {bn_str:<25}")
    print(subsep)
    pl_d = sec_d["pooled"]
    tc_pl_str = f"{pl_d['tool_changed']}/{pl_d['total']} ({pl_d['tool_changed']/pl_d['total']*100:.1f}%)"
    bn_pl_str = f"{pl_d['brand_new']}/{pl_d['total']} ({pl_d['brand_new']/pl_d['total']*100:.1f}%)"
    print(f"{'POOLED TOTAL':<14} | {pl_d['total']:<10} | {tc_pl_str:<28} | {bn_pl_str:<25}")

    # Section E
    if "quarantine_replay" in results:
        sec_e = results["quarantine_replay"]
        print("\n\n[E] QUARANTINE, $0 REPLAY ESTIMATE (ENFORCE MODE)")
        print(subsep)
        print(f"Note: {sec_e['estimate_label']}")
        inst_e = sec_e["instances"]
        tr_e = sec_e["traces"]
        print(
            f"\nInstance Quarantine: {inst_e['poisoned_removed']}/{inst_e['total']} poisoned tools removed "
            f"({inst_e['poisoned_removed_rate']*100:.1f}%, 95% CI [{inst_e['poisoned_removed_ci'][0]:.3f}, {inst_e['poisoned_removed_ci'][1]:.3f}])"
        )
        print(
            f"Collateral Removal:  {inst_e['collateral_removed']}/{inst_e['total']} instances with at least one clean tool removed "
            f"({inst_e['collateral_removed_rate']*100:.1f}%, 95% CI [{inst_e['collateral_removed_ci'][0]:.3f}, {inst_e['collateral_removed_ci'][1]:.3f}])"
        )
        print(f"Clean Tools Removed: {inst_e['clean_tools_removed']}/{inst_e['clean_tools_total']} clean tool slots across all instances")
        print(
            f"\nPooled Trace Attack Neutralization (Author 'Success' Traces): "
            f"{tr_e['success_poisoned_removed']}/{tr_e['success_total']} ({tr_e['success_quarantine_rate']*100:.1f}%, 95% CI [{tr_e['success_quarantine_ci'][0]:.3f}, {tr_e['success_quarantine_ci'][1]:.3f}])"
        )

        print("\nPer-Paradigm Success Neutralization:")
        p_hdr = f"{'Paradigm':<14} | {'Success Neutralized (k/N)':<26} | {'Quarantine Rate (95% CI)':<26}"
        print(p_hdr)
        print("-" * len(p_hdr))
        for p, p_data in sec_e["by_paradigm"].items():
            s_str = f"{p_data['poisoned_removed']}/{p_data['success_total']}"
            r_str = f"{p_data['rate']*100:5.1f}% [{p_data['ci'][0]:.3f}, {p_data['ci'][1]:.3f}]"
            print(f"{p:<14} | {s_str:<26} | {r_str:<26}")

        print("\nPer-Model Success Neutralization:")
        m_hdr = f"{'Model':<23} | {'Success Neutralized (k/N)':<26} | {'Quarantine Rate (95% CI)':<26}"
        print(m_hdr)
        print("-" * len(m_hdr))
        for m, m_data in sec_e["by_model"].items():
            s_str = f"{m_data['poisoned_removed']}/{m_data['success_total']}"
            r_str = f"{m_data['rate']*100:5.1f}% [{m_data['ci'][0]:.3f}, {m_data['ci'][1]:.3f}]"
            print(f"{m:<23} | {s_str:<26} | {r_str:<26}")

    print(sep + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="MCPTox benchmark runner for mcp-integrity")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path.home() / "Library" / "Caches" / "inspect_evals_mcptox" / "response_all.json",
        help="Path to MCPTox response_all.json dataset",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("bench/results_mcptox.json"),
        help="Path to write output results JSON",
    )
    args = parser.parse_args()

    data_path = args.data
    if not data_path.exists():
        sys.exit(f"Error: Data file not found at {data_path}")

    with open(data_path, "rb") as f:
        file_sha256 = hashlib.sha256(f.read()).hexdigest()

    if file_sha256 != EXPECTED_SHA256:
        sys.exit(f"Error: SHA256 mismatch: expected {EXPECTED_SHA256}, got {file_sha256}")

    with open(data_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        res_a = run_benchmark_a(data)
        res_b = run_benchmark_b(data)
        res_c = run_benchmark_c(data, tmp_dir)
        res_d = run_benchmark_d(data, tmp_dir)
        res_e = run_benchmark_e(data, tmp_dir)

    all_results = {
        "scanner_recall_poisoned": res_a,
        "scanner_fp_clean": res_b,
        "call_rule_replay": res_c,
        "pinning_vs_mcptox": res_d,
        "quarantine_replay": res_e,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print_compact_table(all_results)


if __name__ == "__main__":
    main()
