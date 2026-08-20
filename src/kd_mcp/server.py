"""
kd_mcp.server -- MCP server wrapping kd.exe for Windows kernel debugging.

Spawns kd.exe as a subprocess and exposes its functionality as MCP tools.
Handles KDNET connections, breakpoints, memory reads, and register inspection
without the threading limitations of DbgEng COM wrappers.

Environment variables:
    KD_EXE  Path to kd.exe (default: WDK x64 location)
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Optional, Union

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KD_EXE = os.environ.get(
    "KD_EXE",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
)

# kd.exe prompt variants: "kd> ", "0: kd> ", "1: kd> "
_PROMPT_RE = re.compile(r"\d*:?\s*kd>\s*$")
_CONNECTED_RE = re.compile(r"Kernel Debugger connection established", re.IGNORECASE)


def _send_windows_ctrl_break(process_id: int) -> None:
    """Send Ctrl+Break to a process running in a different Windows console."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.FreeConsole.argtypes = []
    kernel32.FreeConsole.restype = wintypes.BOOL
    kernel32.AttachConsole.argtypes = [wintypes.DWORD]
    kernel32.AttachConsole.restype = wintypes.BOOL
    kernel32.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.GenerateConsoleCtrlEvent.restype = wintypes.BOOL

    # kd.exe is launched with CREATE_NEW_CONSOLE. GenerateConsoleCtrlEvent can
    # only target a process group in the caller's current console, so attach to
    # the debugger's console before sending CTRL_BREAK_EVENT.
    kernel32.FreeConsole()
    attached = False
    try:
        if not kernel32.AttachConsole(process_id):
            raise ctypes.WinError(ctypes.get_last_error())
        attached = True
        if not kernel32.GenerateConsoleCtrlEvent(
            signal.CTRL_BREAK_EVENT, process_id
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # Keep the console attached briefly so Windows can deliver the event.
        time.sleep(0.25)
    finally:
        if attached:
            kernel32.FreeConsole()
        # Restore the server's parent console when one exists. The MCP stdio
        # pipes remain valid even when the OpenSSH process has no console.
        kernel32.AttachConsole(wintypes.DWORD(-1).value)

# ---------------------------------------------------------------------------
# KdProcess -- subprocess wrapper with expect-style I/O
# ---------------------------------------------------------------------------

class KdProcess:
    """
    Wraps kd.exe. Reader thread accumulates stdout; expect() scans it for
    a pattern with a deadline, returning everything up to and including the
    match.
    """

    def __init__(self, args: list[str]) -> None:
        startupinfo = None
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            creationflags |= subprocess.CREATE_NEW_CONSOLE

        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=-1,
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
        self._buf = ""
        self._lock = threading.Lock()
        self._ev = threading.Event()
        self._th = threading.Thread(target=self._reader, daemon=True, name="kd-reader")
        self._th.start()

    # -- reader thread -------------------------------------------------------

    def _reader(self) -> None:
        while True:
            try:
                # read1: returns whatever is in the pipe buffer immediately;
                # blocks only until at least 1 byte is available.
                chunk = self.proc.stdout.read1(4096)  # type: ignore[attr-defined]
            except (OSError, ValueError):
                self._ev.set()
                break
            if not chunk:
                if self.proc.poll() is not None:
                    self._ev.set()
                    break
                time.sleep(0.01)
                continue
            with self._lock:
                self._buf += chunk.decode("utf-8", errors="replace")
            self._ev.set()

    # -- public API ----------------------------------------------------------

    def expect(self, pattern: re.Pattern, timeout: float = 30.0) -> str:
        """
        Accumulate stdout until pattern matches anywhere in the buffer.
        Returns all accumulated text (including the match).
        Raises TimeoutError on timeout, RuntimeError if kd.exe exits.
        """
        accumulated = ""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                accumulated += self._buf
                self._buf = ""
            if pattern.search(accumulated):
                return accumulated
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"kd.exe exited (code {self.proc.returncode}). "
                    f"Last output:\n{accumulated[-1000:]}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout ({timeout}s) waiting for pattern. "
                    f"Last output:\n{accumulated[-2000:]}"
                )
            self._ev.wait(min(remaining, 0.15))
            self._ev.clear()

    def sendline(self, cmd: str) -> None:
        self.proc.stdin.write((cmd + "\r\n").encode())
        self.proc.stdin.flush()

    def send_break(self) -> None:
        """Send Ctrl+Break to kd.exe -- triggers kernel break-in over KDNET."""
        _send_windows_ctrl_break(self.proc.pid)

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        for fn in (self.proc.stdin.close, self.proc.terminate, self.proc.kill):
            try:
                fn()
            except Exception:
                pass

    def drain(self) -> None:
        """Discard any buffered output."""
        with self._lock:
            self._buf = ""


# ---------------------------------------------------------------------------
# KdNamedPipe -- named-pipe wrapper with the same interface as KdProcess
# ---------------------------------------------------------------------------

class KdNamedPipe:
    """
    Wraps a Windows named pipe that kd.exe connects to via -k com:pipe,port=<name>.
    The pipe is created here; kd.exe is launched separately and connects as a client.
    Provides the same public API as KdProcess so all MCP tools work unchanged.
    """

    def __init__(self, pipe_name: str, args: list[str]) -> None:
        import win32event
        import win32file
        import win32pipe

        self.pipe_name = pipe_name
        self._buf = ""
        self._lock = threading.Lock()
        self._ev = threading.Event()
        self._shutdown = threading.Event()
        self._pipe: Optional[object] = None
        self.proc: Optional[subprocess.Popen] = None
        self._th: Optional[threading.Thread] = None

        # Create the named pipe server side (byte-mode for COM serial stream).
        self._pipe = win32pipe.CreateNamedPipe(
            pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_BYTE
            | win32pipe.PIPE_READMODE_BYTE
            | win32pipe.PIPE_WAIT,
            255,                 # max instances
            4096,               # out buffer
            4096,               # in buffer
            0,                  # default timeout
            None,               # security
        )

        try:
            # Launch kd.exe which will connect to the pipe.
            self.proc = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

            # Wait for kd.exe to connect to the pipe (60s timeout).
            overlapped = win32file.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
            try:
                win32file.ConnectNamedPipe(self._pipe, overlapped)
                rc = win32event.WaitForSingleObject(overlapped.hEvent, 60_000)
                if rc != win32event.WAIT_OBJECT_0:
                    raise TimeoutError(
                        f"Timeout waiting for kd.exe to connect to {pipe_name}"
                    )
            finally:
                win32file.CloseHandle(overlapped.hEvent)
        except:
            # Clean up pipe and process on any failure.
            self._cleanup_on_init_failure()
            raise

        self._th = threading.Thread(target=self._reader, daemon=True, name="kd-np-reader")
        self._th.start()

    def _cleanup_on_init_failure(self) -> None:
        """Clean up pipe handle and kd.exe process if __init__ fails partway."""
        import win32file
        if self._pipe is not None:
            try:
                win32file.CloseHandle(self._pipe)
            except Exception:
                pass
            self._pipe = None
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.kill()
            except Exception:
                pass
            self.proc = None

    def _reader(self) -> None:
        import win32event
        import win32file

        while not self._shutdown.is_set():
            pipe = self._pipe
            if pipe is None:
                break
            evt = None
            try:
                overlapped = win32file.OVERLAPPED()
                evt = win32event.CreateEvent(None, True, False, None)
                overlapped.hEvent = evt
                try:
                    rc, data = win32file.ReadFile(pipe, 4096, overlapped)
                except Exception:
                    break
                if rc == 997:  # ERROR_IO_PENDING
                    # Wait with periodic checks so shutdown can interrupt.
                    while not self._shutdown.is_set():
                        wrc = win32event.WaitForSingleObject(evt, 500)
                        if wrc == win32event.WAIT_OBJECT_0:
                            break
                    if self._shutdown.is_set():
                        break
                    try:
                        _, data = win32file.GetOverlappedResult(pipe, overlapped, False)
                    except Exception:
                        break
                elif rc != 0:
                    # Unexpected error (e.g., broken pipe).
                    break
                if not data:
                    if self.proc and self.proc.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue
                with self._lock:
                    self._buf += data.decode("utf-8", errors="replace")
                self._ev.set()
            except Exception:
                break
            finally:
                if evt is not None:
                    try:
                        win32file.CloseHandle(evt)
                    except Exception:
                        pass
        self._ev.set()

    # -- public API (same as KdProcess) ------------------------------------

    def expect(self, pattern: re.Pattern, timeout: float = 30.0) -> str:
        accumulated = ""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                accumulated += self._buf
                self._buf = ""
            if pattern.search(accumulated):
                return accumulated
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(
                    f"kd.exe exited (code {self.proc.returncode}). "
                    f"Last output:\n{accumulated[-1000:]}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout ({timeout}s) waiting for pattern. "
                    f"Last output:\n{accumulated[-2000:]}"
                )
            self._ev.wait(min(remaining, 0.15))
            self._ev.clear()

    def sendline(self, cmd: str) -> None:
        import win32file
        if self._pipe is None:
            raise RuntimeError("Pipe is closed -- not connected.")
        win32file.WriteFile(self._pipe, (cmd + "\r\n").encode())

    def send_break(self) -> None:
        if self.proc:
            try:
                os.kill(self.proc.pid, signal.CTRL_BREAK_EVENT)
            except Exception:
                pass

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def kill(self) -> None:
        import win32file
        import win32pipe
        # Signal the reader thread to stop.
        self._shutdown.set()
        if self._pipe is not None:
            # Cancel any pending overlapped I/O on the pipe.
            try:
                win32file.CancelIoEx(self._pipe, None)
            except Exception:
                pass
            try:
                win32pipe.DisconnectNamedPipe(self._pipe)
            except Exception:
                pass
        # Wait for the reader thread to exit before closing the handle.
        if self._th is not None:
            self._th.join(timeout=2)
        if self._pipe is not None:
            try:
                win32file.CloseHandle(self._pipe)
            except Exception:
                pass
            self._pipe = None
        if self.proc is not None:
            for fn in (self.proc.terminate, self.proc.kill):
                try:
                    fn()
                except Exception:
                    pass

    def drain(self) -> None:
        with self._lock:
            self._buf = ""


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

class _State:
    kd: Optional[Union[KdProcess, KdNamedPipe]] = None

STATE = _State()
mcp = FastMCP("kd")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require() -> Union[KdProcess, KdNamedPipe]:
    if STATE.kd is None or not STATE.kd.is_alive():
        raise RuntimeError("Not connected -- call kernel_attach first.")
    return STATE.kd


def _cmd(cmd: str, timeout: float = 20.0) -> str:
    """Send a command, wait for the next kd> prompt, return output (prompt stripped)."""
    kd = _require()
    kd.drain()
    kd.sendline(cmd)
    raw = kd.expect(_PROMPT_RE, timeout=timeout)
    # Strip the trailing prompt and leading echo of our command.
    out = _PROMPT_RE.sub("", raw).strip()
    # Remove first line if it looks like the command echo.
    lines = out.splitlines()
    if lines and lines[0].strip() == cmd.strip():
        out = "\n".join(lines[1:]).strip()
    return out


def _kill_stale_kd(pipe_name: str) -> None:
    """Kill any kd.exe processes left over from a previous server session.

    After a server restart STATE.kd is None, but a stale kd.exe from the
    old session may still be running -- holding the named pipe open (causing
    ERROR_PIPE_BUSY 231) or keeping the kernel debug connection locked
    ("another debugger is connected").  Kill *all* kd.exe processes to
    guarantee a clean slate.
    """
    try:
        subprocess.run(
            ["taskkill", "/F", "/IM", "kd.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        # Give the OS a moment to release pipe handles and debug sessions.
        time.sleep(1.0)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# MCP tools -- session
# ---------------------------------------------------------------------------

@mcp.tool()
def kernel_attach(
    connect_string: str,
    reset_vm: str = "",
    timeout: int = 90,
) -> dict:
    """
    Launch kd.exe and connect to a kernel over KDNET.

    kd.exe may exit immediately if the target is unreachable; this tool will
    respawn it until the full timeout expires so it catches the KDNET hello
    packet whenever the target becomes ready (e.g. after a VM reboot).

    Args:
        connect_string: KDNET string, e.g. "net:port=50000,key=1.2.3.4.5"
        reset_vm:       Hyper-V VM name to hard-reset 2 seconds after kd.exe
                        starts (so kd catches the boot-time KDNET packet).
        timeout:        Total seconds to keep trying for a connection (default 90).

    Returns: {status, kernel_version, attempts, output} or {status, message}
    """
    # Kill any previous session.
    if STATE.kd and STATE.kd.is_alive():
        try:
            STATE.kd.sendline("q")
            time.sleep(0.4)
        except Exception:
            pass
        STATE.kd.kill()
    STATE.kd = None

    args = [KD_EXE, "-bonc", "-k", connect_string]

    try:
        STATE.kd = KdProcess(args)
    except OSError as exc:
        return {"status": "error", "message": f"Failed to launch kd.exe: {exc}"}

    if reset_vm:
        subprocess.Popen(
            [
                "powershell", "-NoProfile", "-Command",
                f"Start-Sleep -Seconds 2; Restart-VM -Name '{reset_vm}' -Force",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    deadline = time.monotonic() + timeout
    attempt = 0
    last_error = "Timeout waiting for KDNET connection"

    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            # A running target may establish KDNET without stopping at a kd>
            # prompt. Return once the debugger reports a completed handshake;
            # callers can then use break_in to stop the target explicitly.
            out = STATE.kd.expect(_CONNECTED_RE, timeout=remaining)
            ver = re.search(r"Windows \S+ \d+ \S+ x64", out)
            return {
                "status": "connected",
                "attempts": attempt,
                "kernel_version": ver.group(0) if ver else "unknown",
                "output": out[-600:].strip(),
            }
        except RuntimeError as exc:
            # kd.exe exited (connection refused, wrong key, etc.) -- respawn and retry
            last_error = str(exc)
            STATE.kd.kill()
            STATE.kd = None
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                break
            time.sleep(1)
            try:
                STATE.kd = KdProcess(args)
            except OSError as oserr:
                STATE.kd = None
                return {"status": "error", "message": f"Failed to launch kd.exe: {oserr}"}
        except TimeoutError as exc:
            # Full timeout elapsed in a single attempt -- no point retrying
            last_error = str(exc)
            STATE.kd.kill()
            STATE.kd = None
            break

    # Ensure STATE is clean so subsequent calls get a clear "not connected" error
    if STATE.kd is not None:
        STATE.kd.kill()
        STATE.kd = None
    return {"status": "error", "attempts": attempt, "message": last_error}


@mcp.tool()
def status() -> dict:
    """Return current debugger connection state."""
    if STATE.kd is None or not STATE.kd.is_alive():
        return {"connected": False}
    return {"connected": True, "pid": STATE.kd.proc.pid if STATE.kd.proc else None}


@mcp.tool()
def detach() -> dict:
    """Quit kd.exe and end the debugging session."""
    if STATE.kd:
        try:
            STATE.kd.sendline("q")
            time.sleep(0.4)
        except Exception:
            pass
        STATE.kd.kill()
    STATE.kd = None
    return {"status": "disconnected"}


@mcp.tool()
def kernel_attach_pipe(
    pipe_name: str = r"\\.\pipe\kdpipe",
    timeout: int = 60,
) -> dict:
    """
    Launch kd.exe connected over a named pipe (com:pipe transport).

    Connects kd.exe to an existing named pipe (typically exposed by a VM's
    virtual serial port).  All subsequent tools (breakpoints, memory reads,
    etc.) work the same as with KDNET.

    Args:
        pipe_name: Windows named-pipe path (default ``\\\\.\\pipe\\kdpipe``).
        timeout:   Seconds to wait for kd.exe to connect (default 60).

    Returns: {status, kernel_version, output} or {status, message}
    """
    # Kill any previous session we know about.
    if STATE.kd and STATE.kd.is_alive():
        try:
            STATE.kd.sendline("q")
            time.sleep(0.4)
        except Exception:
            pass
        STATE.kd.kill()
    STATE.kd = None

    # Kill stale kd.exe processes left over from a previous server instance
    # that may still hold the kernel debug connection.
    _kill_stale_kd(pipe_name)

    # Let kd.exe connect to the VM's existing pipe as a client.
    # -bonc      -- break on connection automatically (sends break packet natively).
    # resets=0   -- don't send reset packets (avoids handshake confusion).
    # reconnect  -- keep trying if the initial handshake fails.
    args = [KD_EXE, "-bonc", "-k", f"com:pipe,port={pipe_name},resets=0,reconnect"]

    try:
        STATE.kd = KdProcess(args)
    except OSError as exc:
        return {"status": "error", "message": f"Failed to launch kd.exe: {exc}"}

    try:
        # Since we use -bonc, kd.exe will automatically break in as soon as it connects.
        out = STATE.kd.expect(_PROMPT_RE, timeout=float(timeout))
        ver = re.search(r"Windows \S+ \d+ \S+ x64", out)
        return {
            "status": "connected",
            "kernel_version": ver.group(0) if ver else "unknown",
            "output": out[-600:].strip(),
        }
    except (TimeoutError, RuntimeError) as exc:
        STATE.kd.kill()
        STATE.kd = None
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# MCP tools -- execution control
# ---------------------------------------------------------------------------

@mcp.tool()
def go(timeout: int = 120) -> dict:
    """
    Resume kernel execution (g) and wait for the next break event.

    Args:
        timeout: Seconds to wait for the next break (default 120).

    Returns: {status, output}
    """
    kd = _require()
    kd.drain()
    kd.sendline("g")
    try:
        out = kd.expect(_PROMPT_RE, timeout=float(timeout))
        return {"status": "break", "output": out.strip()}
    except TimeoutError as exc:
        return {"status": "timeout", "error": str(exc)}
    except RuntimeError as exc:
        return {"status": "error", "error": str(exc)}


@mcp.tool()
def break_in(timeout: int = 15) -> dict:
    """
    Force a break into the running kernel (Ctrl+Break / NMI over KDNET).

    Args:
        timeout: Seconds to wait for the break event (default 15).

    Returns: {status, output}
    """
    kd = _require()
    kd.drain()
    kd.send_break()
    try:
        out = kd.expect(_PROMPT_RE, timeout=float(timeout))
        return {"status": "break", "output": out.strip()}
    except TimeoutError:
        return {"status": "sent", "message": "Break signal sent; no prompt yet."}


@mcp.tool()
def step_into() -> dict:
    """Single-step into next instruction (t)."""
    try:
        return {"output": _cmd("t", timeout=10)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def step_over() -> dict:
    """Step over next instruction (p)."""
    try:
        return {"output": _cmd("p", timeout=10)}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# MCP tools -- breakpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def bp(address: str, once: bool = False) -> dict:
    """
    Set a breakpoint.

    Args:
        address: Address or symbol -- e.g. "nt!NtCreateFile" or "fffff805`1234abcd"
        once:    One-shot breakpoint (cleared after first hit).

    Returns: {output}
    """
    prefix = "bp /1" if once else "bp"
    try:
        return {"output": _cmd(f"{prefix} {address}") or "(breakpoint set)"}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def hw_bp(address: str, width: int = 4, access: str = "e") -> dict:
    """
    Set a hardware breakpoint (ba command).

    Args:
        address: Target address.
        width:   Access width in bytes: 1, 2, 4, or 8 (default 4).
        access:  Access type -- "e"=execute, "r"=read, "w"=write (default "e").

    Returns: {output}
    """
    try:
        return {"output": _cmd(f"ba {access}{width} {address}") or "(hw bp set)"}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_bps() -> dict:
    """List all breakpoints (bl)."""
    try:
        return {"output": _cmd("bl")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def remove_bp(bp_id: str = "*") -> dict:
    """
    Remove a breakpoint.

    Args:
        bp_id: Breakpoint number, or '*' to clear all (default '*').
    """
    try:
        return {"output": _cmd(f"bc {bp_id}") or "(done)"}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# MCP tools -- inspection
# ---------------------------------------------------------------------------

@mcp.tool()
def raw(cmd: str, timeout: int = 20) -> dict:
    """
    Execute any raw kd command and return its output.

    Examples:
        "lm", "!process 0 0", "dt nt!_EPROCESS @$proc",
        "r", "k 20", "!token", "vertarget"

    Args:
        cmd:     kd command string.
        timeout: Seconds to wait for the prompt (default 20).
    """
    try:
        return {"output": _cmd(cmd, timeout=float(timeout))}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def get_regs() -> dict:
    """Read general-purpose registers at the current break context (r)."""
    try:
        return {"output": _cmd("r")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def read_mem(address: str, count: int = 16, width: int = 1) -> dict:
    """
    Read memory (db/dw/dd/dq).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
        count:   Number of units (default 16).
        width:   Unit bytes -- 1=byte, 2=word, 4=dword, 8=qword (default 1).
    """
    cmd_map = {1: "db", 2: "dw", 4: "dd", 8: "dq"}
    kd_cmd = f"{cmd_map.get(width, 'db')} {address} L{count:x}"
    try:
        return {"output": _cmd(kd_cmd)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def stack_trace(frames: int = 20) -> dict:
    """
    Show the current call stack (k).

    Args:
        frames: Number of frames (default 20).
    """
    try:
        return {"output": _cmd(f"k {frames}")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def whereami() -> dict:
    """Show current RIP, its nearest symbol, and the top 5 stack frames."""
    try:
        rip_out = _cmd("r rip")
        m = re.search(r"rip=([0-9a-f`]+)", rip_out, re.IGNORECASE)
        rip = m.group(1) if m else "@rip"
        return {
            "rip": rip_out,
            "symbol": _cmd(f"ln {rip}"),
            "stack": _cmd("k 5"),
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_modules(pattern: str = "") -> dict:
    """
    List loaded kernel modules (lm).

    Args:
        pattern: Optional name glob, e.g. "mmc*".
    """
    cmd = f"lm m {pattern}" if pattern else "lm"
    try:
        return {"output": _cmd(cmd, timeout=30)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def find_symbol(pattern: str) -> dict:
    """
    Resolve symbol pattern to addresses (x command).

    Args:
        pattern: Symbol glob, e.g. "nt!NtCreate*" or "mmc!ScOnOpen*".
    """
    try:
        return {"output": _cmd(f"x {pattern}", timeout=30)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def addr_to_symbol(address: str) -> dict:
    """
    Resolve an address to its nearest symbol (ln).

    Args:
        address: Hex address, e.g. "fffff805`12345678".
    """
    try:
        return {"output": _cmd(f"ln {address}")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def set_sympath(path: str = "") -> dict:
    """
    Set or show the symbol search path (.sympath).

    Args:
        path: Symbol path string.  Omit to just query the current path.
              Example: "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
    """
    cmd = f".sympath {path}" if path else ".sympath"
    try:
        return {"output": _cmd(cmd, timeout=60)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def reload_symbols(module: str = "") -> dict:
    """
    Reload symbol information (.reload).

    Args:
        module: Specific module to reload, e.g. "mmc.exe".  Empty = all.
    """
    cmd = f".reload {module}" if module else ".reload"
    try:
        return {"output": _cmd(cmd, timeout=60)}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global KD_EXE
    if not os.path.exists(KD_EXE):
        import shutil
        found = shutil.which("kd.exe") or shutil.which("kd")
        if found:
            KD_EXE = found
        else:
            print(f"ERROR: kd.exe not found at {KD_EXE} and not in PATH.", file=sys.stderr)
            print("Set KD_EXE environment variable to point to kd.exe.", file=sys.stderr)
            sys.exit(1)

    print("kd MCP server starting (stdio, named pipe available)...", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
