import ctypes
import pathlib
import queue
import sys
import time
import types
import unittest
from unittest import mock


class _FakeFastMCP:
    def __init__(self, _name):
        pass

    def tool(self):
        return lambda function: function


fastmcp = types.ModuleType("mcp.server.fastmcp")
fastmcp.FastMCP = _FakeFastMCP
sys.modules.setdefault("mcp", types.ModuleType("mcp"))
sys.modules.setdefault("mcp.server", types.ModuleType("mcp.server"))
sys.modules.setdefault("mcp.server.fastmcp", fastmcp)
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "src"))

from kd_mcp import server  # noqa: E402


class _FakeKd:
    def __init__(self):
        self.expected_pattern = None

    def expect(self, pattern, timeout):
        self.expected_pattern = pattern
        return (
            "Connected to Windows 10 22621 x64 target\n"
            "Kernel Debugger connection established.\n"
        )

    def is_alive(self):
        return True

    def kill(self):
        pass


class _ScriptedStdout:
    def __init__(self):
        self._items = queue.Queue()

    def feed(self, item):
        self._items.put(item)

    def read1(self, _size):
        item = self._items.get()
        if isinstance(item, BaseException):
            raise item
        return item


class _FakeStdin:
    def __init__(self, on_flush=None):
        self.writes = []
        self.closed = False
        self._on_flush = on_flush

    def write(self, value):
        self.writes.append(value)
        return len(value)

    def flush(self):
        if self._on_flush is not None:
            self._on_flush()

    def close(self):
        self.closed = True


class _FakeProcess:
    def __init__(self, stdout, on_flush=None):
        self.stdout = stdout
        self.stdin = _FakeStdin(on_flush)
        self.returncode = None
        self.pid = 4321

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0
        self.stdout.feed(b"")

    def kill(self):
        self.returncode = 0
        self.stdout.feed(b"")


def _kd_process(stdout=None, on_flush=None):
    output = stdout or _ScriptedStdout()
    process = _FakeProcess(output, on_flush)
    with (
        mock.patch.object(server.subprocess, "Popen", return_value=process),
        mock.patch.object(
            server.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, create=True
        ),
    ):
        kd = server.KdProcess(["kd.exe"])
    return kd, process, output


def _wait_for(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("condition did not become true")


def _stop(kd, process, output):
    process.returncode = 0
    output.feed(b"")
    kd._th.join(timeout=1)


class KernelAttachTests(unittest.TestCase):
    def tearDown(self):
        server.STATE.kd = None

    def test_attach_completes_on_debugger_handshake_without_prompt(self):
        fake_kd = _FakeKd()
        with mock.patch.object(server, "KdProcess", return_value=fake_kd):
            result = server.kernel_attach("net:port=50000,key=example", timeout=1)

        self.assertEqual("connected", result["status"])
        self.assertIs(server._CONNECTED_RE, fake_kd.expected_pattern)
        self.assertIs(fake_kd, server.STATE.kd)

    def test_attach_disposes_unusable_prior_process_before_replacement(self):
        prior = mock.MagicMock()
        prior.is_alive.return_value = False
        server.STATE.kd = prior
        fake_kd = _FakeKd()

        with mock.patch.object(server, "KdProcess", return_value=fake_kd):
            result = server.kernel_attach(
                "net:port=50000,key=example", timeout=1
            )

        self.assertEqual("connected", result["status"])
        prior.kill.assert_called_once_with()
        prior.sendline.assert_not_called()
        self.assertIs(fake_kd, server.STATE.kd)


class CtrlBreakTests(unittest.TestCase):
    def test_send_break_attaches_to_debugger_console_and_targets_process_group(self):
        kernel32 = mock.MagicMock()
        kernel32.AttachConsole.return_value = True
        kernel32.GenerateConsoleCtrlEvent.return_value = True

        with (
            mock.patch("ctypes.WinDLL", return_value=kernel32, create=True),
            mock.patch.object(server.signal, "CTRL_BREAK_EVENT", 1, create=True),
            mock.patch.object(server.time, "sleep") as sleep,
        ):
            server._send_windows_ctrl_break(4321)

        kernel32.AttachConsole.assert_any_call(4321)
        kernel32.GenerateConsoleCtrlEvent.assert_called_once_with(1, 4321)
        kernel32.FreeConsole.assert_called()
        kernel32.AttachConsole.assert_any_call(ctypes.c_ulong(-1).value)
        sleep.assert_called_once_with(0.25)


class ReaderHealthTests(unittest.TestCase):
    def tearDown(self):
        server.STATE.kd = None

    def test_reader_os_error_fails_prompt_wait_while_process_is_alive(self):
        output = _ScriptedStdout()
        error = OSError(5, "fake read failure")
        error.winerror = 109
        output.feed(error)
        kd, process, output = _kd_process(output)
        kd._th.join(timeout=1)

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "reader stopped"):
            kd.expect(server._PROMPT_RE, timeout=5)
        self.assertLess(time.monotonic() - started, 0.5)
        health = kd._health_snapshot()
        self.assertEqual("OS_ERROR", health["reader_terminal"])
        self.assertEqual(5, health["reader_errno"])
        self.assertEqual(109, health["reader_winerror"])
        self.assertFalse(health["reader_thread_alive"])
        self.assertIsNone(process.poll())
        server.STATE.kd = kd
        self.assertEqual({"connected": False}, server.status())
        self.assertEqual(0, process.poll())
        self.assertIsNone(server.STATE.kd)

    def test_reader_value_error_is_terminal(self):
        output = _ScriptedStdout()
        output.feed(ValueError("fake closed output"))
        kd, process, output = _kd_process(output)
        kd._th.join(timeout=1)

        with self.assertRaisesRegex(RuntimeError, "reader stopped"):
            kd.expect(server._PROMPT_RE, timeout=5)
        health = kd._health_snapshot()
        self.assertEqual("VALUE_ERROR", health["reader_terminal"])
        self.assertIsNone(health["reader_errno"])
        self.assertIsNone(health["reader_winerror"])
        self.assertIsNone(process.poll())

    def test_blocking_stdout_empty_bytes_is_eof_even_if_process_is_alive(self):
        output = _ScriptedStdout()
        output.feed(b"")
        kd, process, output = _kd_process(output)
        kd._th.join(timeout=1)

        with self.assertRaisesRegex(RuntimeError, "reader stopped"):
            kd.expect(server._PROMPT_RE, timeout=5)
        health = kd._health_snapshot()
        self.assertEqual("EOF", health["reader_terminal"])
        self.assertFalse(health["command_channel_usable"])
        self.assertIsNone(process.poll())

    def test_break_prompt_can_precede_reader_terminal_and_next_command_fails(self):
        kd, process, output = _kd_process()
        server.STATE.kd = kd

        def send_break(_pid):
            output.feed(b"break output\r\n1: kd> ")

        with mock.patch.object(server, "_send_windows_ctrl_break", send_break):
            result = server.break_in(timeout=1)
        self.assertEqual("break", result["status"])
        self.assertIn("1: kd>", result["output"])

        output.feed(OSError(5, "reader stopped after prompt"))
        kd._th.join(timeout=1)
        command = server.list_modules("win32kfull")
        self.assertIn("error", command)
        self.assertIn("reader_terminal=OS_ERROR", command["error"])
        self.assertEqual([], process.stdin.writes)

    def test_healthy_zero_output_timeout_desynchronizes_and_blocks_late_prompt(self):
        kd, process, output = _kd_process()
        server.STATE.kd = kd

        with self.assertRaisesRegex(TimeoutError, "Command health"):
            server._cmd("lm m win32kfull", timeout=0.02)
        health = kd._health_snapshot()
        self.assertEqual("NONE", health["reader_terminal"])
        self.assertTrue(health["reader_thread_alive"])
        self.assertFalse(health["command_channel_usable"])
        self.assertEqual(1, health["command_sequence"])
        self.assertEqual(1, health["command_failures"])
        self.assertEqual(1, health["prompt_timeouts"])
        self.assertEqual(1, health["last_timeout_command"])

        output.feed(b"late first command output\r\n1: kd> ")
        _wait_for(lambda: bool(kd._buf))
        with self.assertRaisesRegex(RuntimeError, "channel is unusable"):
            server._cmd("lm m second", timeout=0.02)
        self.assertEqual(1, len(process.stdin.writes))
        self.assertEqual({"connected": False}, server.status())
        self.assertEqual(0, process.poll())
        self.assertIsNone(server.STATE.kd)
        _stop(kd, process, output)

    def test_normal_one_colon_kd_prompt_keeps_channel_usable(self):
        output = _ScriptedStdout()

        def respond():
            output.feed(
                b"lm m win32kfull\r\nfffff801 win32kfull.sys\r\n1: kd> "
            )

        kd, process, output = _kd_process(output, respond)
        server.STATE.kd = kd
        result = server._cmd("lm m win32kfull", timeout=1)

        self.assertIn("win32kfull.sys", result)
        health = kd._health_snapshot()
        self.assertTrue(health["command_channel_usable"])
        self.assertEqual(1, health["command_sequence"])
        self.assertEqual(0, health["command_failures"])
        self.assertEqual(0, health["prompt_timeouts"])
        self.assertEqual({"connected": True, "pid": 4321}, server.status())
        _stop(kd, process, output)

    def test_go_timeout_preserves_running_channel_semantics(self):
        kd, process, output = _kd_process()
        server.STATE.kd = kd
        result = server.go(timeout=0.02)

        self.assertEqual("timeout", result["status"])
        health = kd._health_snapshot()
        self.assertTrue(health["command_channel_usable"])
        self.assertEqual(0, health["command_sequence"])
        self.assertEqual(0, health["prompt_timeouts"])
        self.assertEqual({"connected": True, "pid": 4321}, server.status())
        _stop(kd, process, output)


class VersionTests(unittest.TestCase):
    def test_package_versions_are_consistent(self):
        from kd_mcp import __version__

        pyproject = (
            pathlib.Path(__file__).parents[1] / "pyproject.toml"
        ).read_text(encoding="utf-8")
        self.assertEqual("0.1.1", __version__)
        self.assertIn('version = "0.1.1"', pyproject)


class DiagnosticTests(unittest.TestCase):
    def test_list_modules_diagnostic_removes_connect_string_and_key_fields(self):
        rendered = server._redact_diagnostic_error(
            "Timeout. Last output:\n"
            "NeT:port=50000,key=raw-kdnet-secret,foo=bar\n"
            "key = \"secret with spaces\"; safe=field"
        )

        self.assertNotIn("net:", rendered.lower())
        self.assertNotIn("50000", rendered)
        self.assertNotIn("raw-kdnet-secret", rendered)
        self.assertNotIn("secret with spaces", rendered)
        self.assertIn("[REDACTED]", rendered)


if __name__ == "__main__":
    unittest.main()
