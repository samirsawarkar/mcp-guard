import subprocess
import sys
import threading
from typing import BinaryIO, Callable

HookCallable = Callable[[bytes], bytes | None]


class Proxy:
    def __init__(
        self,
        process: subprocess.Popen,
        on_client_line: HookCallable | None = None,
        on_server_line: HookCallable | None = None,
        client_in: BinaryIO | None = None,
        client_out: BinaryIO | None = None,
    ) -> None:
        self.process = process
        self.on_client_line = on_client_line
        self.on_server_line = on_server_line
        self.client_in = client_in if client_in is not None else sys.stdin.buffer
        self.client_out = client_out if client_out is not None else sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._client_done = threading.Event()
        self._server_done = threading.Event()

    def _client_pump(self) -> None:
        if self.process.stdin is None:
            return
        try:
            while not self._server_done.is_set():
                line = self.client_in.readline()
                if not line:
                    break
                if self.on_client_line is not None:
                    transformed = self.on_client_line(line)
                    if transformed is None:
                        continue
                    line = transformed
                self.process.stdin.write(line)
                self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            self._client_done.set()

    def _server_pump(self) -> None:
        if self.process.stdout is None:
            return
        try:
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break
                if self.on_server_line is not None:
                    transformed = self.on_server_line(line)
                    if transformed is None:
                        continue
                    line = transformed
                with self._out_lock:
                    self.client_out.write(line)
                    self.client_out.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            self._server_done.set()

    def run(self) -> int:
        client_thread = threading.Thread(target=self._client_pump, daemon=True)
        server_thread = threading.Thread(target=self._server_pump, daemon=True)

        client_thread.start()
        server_thread.start()

        while not self._client_done.is_set() and not self._server_done.is_set():
            if self.process.poll() is not None:
                break
            self._server_done.wait(timeout=0.05)

        # Client stdin hit EOF or server exited.
        # Close server stdin so child sees EOF if it's reading.
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError:
                pass

        # If server is still alive, terminate cleanly: terminate, wait 2s, kill
        if self.process.poll() is None:
            # Brief pause for clean self-termination upon stdin EOF
            try:
                self.process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass

        if self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                try:
                    self.process.kill()
                    self.process.wait()
                except OSError:
                    pass
            except OSError:
                pass
        else:
            self.process.wait()

        server_thread.join(timeout=0.5)

        return self.process.returncode if self.process.returncode is not None else 0

    def reply(self, line: bytes) -> None:
        with self._out_lock:
            self.client_out.write(line)
            self.client_out.flush()


def run_proxy(
    process: subprocess.Popen,
    on_client_line: HookCallable | None = None,
    on_server_line: HookCallable | None = None,
    guard: Any = None,
) -> int:
    proxy = Proxy(
        process,
        on_client_line=on_client_line,
        on_server_line=on_server_line,
    )
    if guard is not None:
        guard.reply = proxy.reply
        proxy.on_client_line = guard.client_line
        proxy.on_server_line = guard.server_line
    return proxy.run()

