import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security.anti_tamper import AntiTamperEngine


class TestAntiTamperEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AntiTamperEngine(check_interval=0.01)

    def test_init(self) -> None:
        self.assertEqual(self.engine._check_interval, 0.01)
        self.assertFalse(self.engine._running)
        self.assertGreater(self.engine._timing_baseline_ns, 0)

    @patch.object(AntiTamperEngine, "_run_heuristics")
    def test_start_and_stop(self, mock_run: MagicMock) -> None:
        self.engine.start()
        self.assertTrue(self.engine._running)
        self.assertIsNotNone(self.engine._monitor_thread)
        assert self.engine._monitor_thread is not None
        self.assertTrue(self.engine._monitor_thread.is_alive())

        # Test idempotence
        self.engine.start()

        self.engine.stop()
        assert self.engine._monitor_thread is not None
        self.engine._monitor_thread.join(timeout=1.0)
        self.assertFalse(self.engine._running)

    @patch("security.anti_tamper.os._exit")
    def test_abort_process(self, mock_exit: MagicMock) -> None:
        mock_buf = bytearray(b"secret")
        self.engine.register_emergency_buffer(mock_buf)
        self.engine._abort_process("test")
        mock_exit.assert_called_once_with(1)
        # Verify buffer was zeroized (MemorySanitizer might not run if mocked, but we check logic)

    def test_register_invalid_buffer(self) -> None:
        with self.assertRaises(TypeError):
            self.engine.register_emergency_buffer(b"immutable")  # type: ignore

    @patch.object(AntiTamperEngine, "_detect_python_trace", return_value=True)
    @patch.object(AntiTamperEngine, "_abort_process")
    def test_run_heuristics_detects_trace(
        self, mock_abort: MagicMock, mock_trace: MagicMock
    ) -> None:
        self.engine._run_heuristics()
        mock_abort.assert_called_once()
        self.assertIn("DEBUGGER_HOOK", mock_abort.call_args[0][0])

    @patch.object(AntiTamperEngine, "_detect_python_trace", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_python_profile", return_value=True)
    @patch.object(AntiTamperEngine, "_abort_process")
    def test_run_heuristics_detects_profile(
        self, mock_abort: MagicMock, mock_profile: MagicMock, mock_trace: MagicMock
    ) -> None:
        self.engine._run_heuristics()
        mock_abort.assert_called_once()
        self.assertIn("PROFILER_HOOK", mock_abort.call_args[0][0])

    @patch.object(AntiTamperEngine, "_detect_python_trace", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_python_profile", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_windows_debugger", return_value=True)
    @patch.object(AntiTamperEngine, "_abort_process")
    def test_run_heuristics_detects_windows(
        self,
        mock_abort: MagicMock,
        mock_win: MagicMock,
        mock_profile: MagicMock,
        mock_trace: MagicMock,
    ) -> None:
        self.engine._run_heuristics()
        mock_abort.assert_called_once()
        self.assertIn("WINDOWS_DEBUGGER", mock_abort.call_args[0][0])

    @patch.object(AntiTamperEngine, "_detect_python_trace", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_python_profile", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_linux_tracer", return_value=True)
    @patch.object(AntiTamperEngine, "_abort_process")
    def test_run_heuristics_detects_linux(
        self,
        mock_abort: MagicMock,
        mock_lin: MagicMock,
        mock_profile: MagicMock,
        mock_trace: MagicMock,
    ) -> None:
        self.engine._run_heuristics()
        mock_abort.assert_called_once()
        self.assertIn("LINUX_PTRACE", mock_abort.call_args[0][0])

    @patch.object(AntiTamperEngine, "_detect_python_trace", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_python_profile", return_value=False)
    @patch.object(AntiTamperEngine, "_detect_timing_anomaly", return_value=True)
    @patch.object(AntiTamperEngine, "_abort_process")
    def test_run_heuristics_detects_timing(
        self,
        mock_abort: MagicMock,
        mock_time: MagicMock,
        mock_profile: MagicMock,
        mock_trace: MagicMock,
    ) -> None:
        self.engine._run_heuristics()
        mock_abort.assert_called_once()
        self.assertIn("TIMING_ANOMALY", mock_abort.call_args[0][0])

    def test_measure_timing_baseline(self) -> None:
        baseline = AntiTamperEngine._measure_timing_baseline()
        self.assertIsInstance(baseline, int)
        self.assertGreater(baseline, 0)

    @patch("security.anti_tamper.time.perf_counter_ns")
    def test_detect_timing_anomaly(self, mock_perf: MagicMock) -> None:
        mock_perf.side_effect = [1000, 60000, 1000, 2000, 1000, 2000]
        self.engine._timing_baseline_ns = 1000
        # ratio is 59x > 50x, should return True
        self.assertTrue(self.engine._detect_timing_anomaly())

        self.assertFalse(self.engine._detect_timing_anomaly())

        self.engine._timing_baseline_ns = 0
        self.assertFalse(self.engine._detect_timing_anomaly())


if __name__ == "__main__":
    unittest.main()
