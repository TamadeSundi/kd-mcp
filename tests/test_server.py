import ctypes
import pathlib
import sys
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


if __name__ == "__main__":
    unittest.main()
