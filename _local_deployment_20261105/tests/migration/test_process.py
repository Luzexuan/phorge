#!/usr/bin/env python3
"""Exercise real cancellation of tiny subprocesses; no Docker or service calls."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('migration_process', ROOT/'scripts/migration_process.py')
process = importlib.util.module_from_spec(spec)
spec.loader.exec_module(process)

CHILD = '''import signal,time,sys
from pathlib import Path
root=Path(sys.argv[1])
def stop(signum, frame):
    raise KeyboardInterrupt()
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
try:
    (root/'ready').write_text(str(__import__('os').getpid()))
    while True: time.sleep(0.02)
except KeyboardInterrupt:
    pass
finally:
    signal.signal(signal.SIGINT,signal.SIG_IGN)
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    (root/'cleanup-start').write_text('recovering')
    time.sleep(0.35)
    (root/'cleanup-complete').write_text('recovered')
'''
PARENT = '''import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('migration_process',sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with (root/'private.log').open('wb') as log:
    result=m.run_backup([sys.executable,root/'child.py',root],cwd=root,stdout=log)
result['cleanupFinishedBeforeReturn']=(root/'cleanup-complete').exists()
(root/'result.json').write_text(json.dumps(result))
'''


class ProcessTests(unittest.TestCase):
    def wait_file(self, path, process_handle):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if path.exists(): return
            if process_handle.poll() is not None:
                self.fail('Fixture process exited before reaching its requested state.')
            time.sleep(0.01)
        self.fail('Fixture process did not reach its requested state.')

    def cancel_real_child(self, signum, repeat=False):
        with tempfile.TemporaryDirectory(prefix='migration-process-test-') as temporary:
            root=Path(temporary)
            (root/'child.py').write_text(CHILD)
            (root/'parent.py').write_text(PARENT)
            parent = subprocess.Popen([sys.executable, root/'parent.py', root,
                                       ROOT/'scripts/migration_process.py'],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                      start_new_session=True)
            try:
                self.wait_file(root/'ready', parent)
                os.kill(parent.pid, signum)
                if repeat:
                    self.wait_file(root/'cleanup-start', parent)
                    os.kill(parent.pid, signal.SIGINT)
                    os.kill(parent.pid, signal.SIGTERM)
                _, errors = parent.communicate(timeout=5)
                self.assertEqual(0, parent.returncode, errors.decode())
                result = json.loads((root/'result.json').read_text())
                self.assertTrue(result['cancelled'])
                self.assertEqual(signum, result['signal'])
                self.assertEqual(128+signum, result['exitCode'])
                self.assertEqual(0, result['returncode'])
                self.assertTrue(result['cleanupFinishedBeforeReturn'])
            finally:
                if parent.poll() is None:
                    # Test emergency cleanup only; the helper itself never kills.
                    parent.kill(); parent.wait()
                    if (root/'ready').exists():
                        try: os.kill(int((root/'ready').read_text()), signal.SIGTERM)
                        except ProcessLookupError: pass

    def test_sigint_waits_for_child_finally(self):
        self.cancel_real_child(signal.SIGINT)

    def test_sigterm_waits_for_child_finally(self):
        self.cancel_real_child(signal.SIGTERM)

    def test_repeated_signals_do_not_kill_recovery(self):
        self.cancel_real_child(signal.SIGINT, repeat=True)

    def test_normal_success_and_failure_return_codes(self):
        before = {s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        with tempfile.TemporaryFile() as log:
            good=process.run_backup([sys.executable,'-c','print("completed")'],stdout=log)
            bad=process.run_backup([sys.executable,'-c','raise SystemExit(7)'],stdout=log)
        self.assertEqual({'returncode':0,'cancelled':False,'signal':None,'exitCode':0},good)
        self.assertEqual(7,bad['returncode']);self.assertFalse(bad['cancelled'])
        self.assertEqual(before,{s:signal.getsignal(s) for s in before})

    def test_spawn_failure_restores_callers_signal_handlers(self):
        before = {s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        with tempfile.TemporaryFile() as log, mock.patch.object(process.subprocess,'Popen',side_effect=OSError('fixture')):
            with self.assertRaises(OSError): process.run_backup(['missing'],stdout=log)
        self.assertEqual(before,{s:signal.getsignal(s) for s in before})

    def test_late_cancel_is_reported_even_if_child_has_successfully_exited(self):
        child=mock.Mock();child.poll.return_value=0
        def wait():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
            return 0
        child.wait.side_effect=wait
        with tempfile.TemporaryFile() as log, mock.patch.object(process.subprocess,'Popen',return_value=child):
            result=process.run_backup(['fixture'],stdout=log)
        self.assertTrue(result['cancelled'])
        self.assertEqual(0,result['returncode'])
        child.send_signal.assert_not_called()


if __name__ == '__main__':
    unittest.main()
