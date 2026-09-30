from __future__ import annotations

from pathlib import Path
import re
import mcp_guard

try:
    import tomllib
except ImportError:
    tomllib = None  # Python < 3.11 fallback


def test_version_matches_pyproject():
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml not found"
    content = pyproject_path.read_text(encoding="utf-8")

    if tomllib is not None:
        data = tomllib.loads(content)
        pyproject_version = data["project"]["version"]
    else:
        match = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', content)
        assert match, "Could not find version in pyproject.toml"
        pyproject_version = match.group(1)

    assert mcp_guard.__version__ == pyproject_version
