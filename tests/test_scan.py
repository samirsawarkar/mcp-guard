from __future__ import annotations

from pathlib import Path

from mcp_guard.scan import scan_description, scan_manifest

FIXTURES_DIR = Path(__file__).parent / "descriptions"


def test_benign_descriptions():
    """Verify benign descriptions yield no findings."""
    for fixture_name in [
        "benign_docs_url.txt",
        "benign_email_noun.txt",
        "benign_long_normal.txt",
    ]:
        text = (FIXTURES_DIR / fixture_name).read_text(encoding="utf-8")
        findings = scan_description(text)
        assert findings == [], f"Expected no findings for {fixture_name}, got {findings}"


def test_poisoned_hidden_instruction():
    text = (FIXTURES_DIR / "poisoned_hidden_instruction.txt").read_text(encoding="utf-8")
    findings = scan_description(text)
    assert "hidden_instruction" in findings


def test_poisoned_exfiltration():
    text = (FIXTURES_DIR / "poisoned_exfiltration.txt").read_text(encoding="utf-8")
    findings = scan_description(text)
    assert "exfiltration_target" in findings


def test_poisoned_sensitive_path():
    text = (FIXTURES_DIR / "poisoned_sensitive_path.txt").read_text(encoding="utf-8")
    findings = scan_description(text)
    assert "sensitive_path" in findings


def test_poisoned_invisible_unicode():
    text = (FIXTURES_DIR / "poisoned_invisible_unicode.txt").read_text(encoding="utf-8")
    findings = scan_description(text)
    assert "invisible_unicode" in findings


def test_poisoned_cross_tool():
    text = (FIXTURES_DIR / "poisoned_cross_tool.txt").read_text(encoding="utf-8")
    manifest = {
        "formatter": text,
        "send_email": "Sends emails to recipients.",
    }
    manifest_findings = scan_manifest(manifest)
    assert "cross_tool_reference" in manifest_findings["formatter"]
    assert "cross_tool_reference" not in manifest_findings["send_email"]
