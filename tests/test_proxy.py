from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcp_integrity.proxy import Proxy


FAKE_SERVER_PATH = Path(__file__).parent / "fake_server.py"


def test_proxy_passthrough_and_byte_fidelity():
    """Verify stdio passthrough, response ordering, and byte-faithful line forwarding."""
    cmd = [
        sys.executable,
        "-m",
        "mcp_integrity.cli",
        "run",
        "--",
        sys.executable,
        str(FAKE_SERVER_PATH),
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None

    req1 = '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}'
    req2 = '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}'
    # Oddly-formatted request: weird key order, unusual whitespace
    req3_odd = '{"params":  {"name": "test"} ,   "method": "tools/call",   "id": 3, "jsonrpc": "2.0"   }'

    requests = [req1, req2, req3_odd]
    for req in requests:
        proc.stdin.write(req.encode("utf-8") + b"\n")
        proc.stdin.flush()

    responses = []
    for _ in range(3):
        line = proc.stdout.readline()
        assert line, "Unexpected EOF while reading response from proxy"
        data = json.loads(line.decode("utf-8"))
        responses.append(data)

    # 1. Matching IDs in order
    assert [r["id"] for r in responses] == [1, 2, 3]

    # 2. Each is valid JSON (already verified by json.loads)
    assert responses[0]["jsonrpc"] == "2.0"
    assert responses[1]["jsonrpc"] == "2.0"
    assert responses[2]["jsonrpc"] == "2.0"

    # 3. Byte fidelity: raw line arrived at fake server completely unchanged
    assert responses[2]["result"]["raw"] == req3_odd

    # Clean shutdown
    proc.stdin.close()
    proc.wait(timeout=5.0)


def test_proxy_exit_on_stdin_close():
    """Verify proxy exits within 5s when client stdin closes, and child is gone."""
    cmd = [
        sys.executable,
        "-m",
        "mcp_integrity.cli",
        "run",
        "--",
        sys.executable,
        str(FAKE_SERVER_PATH),
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None

    # Send initialize request to get child PID
    init_req = '{"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {}}\n'
    proc.stdin.write(init_req.encode("utf-8"))
    proc.stdin.flush()

    resp_line = proc.stdout.readline()
    resp = json.loads(resp_line.decode("utf-8"))
    child_pid = resp["result"]["pid"]

    # Verify child is alive
    os.kill(child_pid, 0)

    # Close stdin on proxy
    start_time = time.time()
    proc.stdin.close()

    # Proxy must exit within 5s
    proc.wait(timeout=5.0)
    elapsed = time.time() - start_time
    assert elapsed < 5.0

    # Verify child is gone
    deadline = time.time() + 2.0
    child_gone = False
    while time.time() < deadline:
        try:
            os.kill(child_pid, 0)
            time.sleep(0.05)
        except ProcessLookupError:
            child_gone = True
            break

    assert child_gone, f"Child process {child_pid} is still running"


def test_proxy_terminates_stubborn_child():
    """Verify proxy forcibly terminates a child that ignores stdin EOF."""
    cmd = [
        sys.executable,
        "-m",
        "mcp_integrity.cli",
        "run",
        "--",
        sys.executable,
        "-c",
        "import time, sys, os; sys.stdout.write(f'{os.getpid()}\\n'); sys.stdout.flush(); [time.sleep(0.1) for _ in range(300)]",
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None

    pid_line = proc.stdout.readline()
    child_pid = int(pid_line.strip())

    os.kill(child_pid, 0)

    # Close stdin
    start_time = time.time()
    proc.stdin.close()

    # Must exit within 5s
    proc.wait(timeout=5.0)
    assert time.time() - start_time < 5.0

    # Verify child is gone
    deadline = time.time() + 2.0
    child_gone = False
    while time.time() < deadline:
        try:
            os.kill(child_pid, 0)
            time.sleep(0.05)
        except ProcessLookupError:
            child_gone = True
            break

    assert child_gone, f"Stubborn child {child_pid} was not terminated"


def test_proxy_hooks_seam():
    """Verify on_client_line and on_server_line hook seam works."""
    # Spawn a simple cat echo server
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.readline()); sys.stdout.flush()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    client_in = io.BytesIO(b'{"hello":"client"}\n')
    client_out = io.BytesIO()

    client_hook_called = []
    server_hook_called = []

    def on_client(line: bytes) -> bytes | None:
        client_hook_called.append(line)
        return b'{"hello":"transformed"}\n'

    def on_server(line: bytes) -> bytes | None:
        server_hook_called.append(line)
        return b'{"server":"response"}\n'

    proxy = Proxy(
        proc,
        on_client_line=on_client,
        on_server_line=on_server,
        client_in=client_in,
        client_out=client_out,
    )
    code = proxy.run()

    assert code == 0
    assert client_hook_called == [b'{"hello":"client"}\n']
    assert server_hook_called == [b'{"hello":"transformed"}\n']
    assert client_out.getvalue() == b'{"server":"response"}\n'
