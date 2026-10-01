from __future__ import annotations

import re
from typing import Dict, List

HIDDEN_INSTRUCTION_RES = [
    re.compile(
        r"\bignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdo\s+not\s+(?:tell|mention|reveal|inform)(?:\s+the)?\s+user\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bbefore\s+(?:calling|using|answering)\b", re.IGNORECASE),
    re.compile(r"\byou\s+must\s+(?:first|always)\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(
        r"<\s*/?\s*(?:important|system|instructions?|hidden|secret)\b[^>]*>",
        re.IGNORECASE,
    ),
]

URL_OR_EMAIL_RE = re.compile(
    r"(?:https?://[^\s<>\"']+|ftp://[^\s<>\"']+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)",
    re.IGNORECASE,
)

EXFIL_KEYWORD_RE = re.compile(
    r"\b(?:send|post|forward|upload|email|transmit|curl)\b",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:~/\.ssh|\bid_rsa\b|\.env\b|\.aws/credentials|/etc/passwd|\.npmrc\b|\.git-credentials\b|\bkeychain\b|\bwallet\b)",
    re.IGNORECASE,
)

INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u202a-\u202e\U000e0000-\U000e007f]"
)

ACTION_WORD_RE = re.compile(r"\b(?:call|use|invoke|run)\b", re.IGNORECASE)


def scan_description(text: str) -> List[str]:
    """Scan a single tool description for suspicious patterns.
    
    Pure function, no state. Returns list of finding labels:
    - 'hidden_instruction'
    - 'exfiltration_target'
    - 'sensitive_path'
    - 'invisible_unicode'
    """
    if not text:
        return []

    findings: List[str] = []

    # 1. hidden_instruction
    if any(pattern.search(text) for pattern in HIDDEN_INSTRUCTION_RES):
        findings.append("hidden_instruction")

    # 2. exfiltration_target
    if URL_OR_EMAIL_RE.search(text) and EXFIL_KEYWORD_RE.search(text):
        findings.append("exfiltration_target")

    # 3. sensitive_path
    if SENSITIVE_PATH_RE.search(text):
        findings.append("sensitive_path")

    # 4. invisible_unicode
    if INVISIBLE_UNICODE_RE.search(text):
        findings.append("invisible_unicode")

    return findings


def scan_manifest(tools: Dict[str, str]) -> Dict[str, List[str]]:
    """Scan all tool descriptions in a manifest and detect cross-tool references.
    
    tools: mapping of tool name -> tool description.
    Returns: mapping of tool name -> list of finding labels.
    """
    results: Dict[str, List[str]] = {}

    for tool_name, desc in tools.items():
        findings = scan_description(desc)

        # 5. cross_tool_reference
        if desc:
            for other_tool in tools.keys():
                if other_tool == tool_name:
                    continue

                pattern = re.compile(r"\b" + re.escape(other_tool) + r"\b", re.IGNORECASE)
                cross_ref_found = False
                for match in pattern.finditer(desc):
                    start, end = match.span()
                    prefix = desc[max(0, start - 40) : start]
                    suffix = desc[end : min(len(desc), end + 40)]
                    if ACTION_WORD_RE.search(prefix) or ACTION_WORD_RE.search(suffix):
                        cross_ref_found = True
                        break

                if cross_ref_found:
                    if "cross_tool_reference" not in findings:
                        findings.append("cross_tool_reference")
                    break

        results[tool_name] = findings

    return results
