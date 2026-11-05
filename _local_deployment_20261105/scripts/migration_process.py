#!/usr/bin/env python3
"""Wait for a backup's own service recovery when its caller is cancelled.

subprocess.run() kills its child when KeyboardInterrupt escapes communicate().
That is unsafe for a backup which must restart stopped application services in
finally. This helper owns only its immediate child: cancellation sends SIGTERM
once, then waits without a SIGKILL fallback. It never signals Docker containers.
"""
from __future__ import annotations

import signal
import subprocess
import threading


def run_backup(argv, *, cwd=None, stdout):
    """Run backup.py with graceful cancellation, returning non-secret status.

``stdout`` must be an open private log file; stderr joins that same file. The
child gets a separate process session, so terminal Ctrl+C reaches this parent
instead of racing a second signal against backup.py's recovery. A first SIGINT
or SIGTERM is forwarded as one SIGTERM to the child PID. Further cancellation
signals do not interrupt its finally block. Existing caller handlers are
restored after the child exits.

The return value has returncode, cancelled, signal and exitCode. A cancelled
child may have completed successfully just before the signal arrived. Therefore
the caller must still inspect its snapshot/manifest or backup-status file and
resume a completed --leave-stopped snapshot if the overall export is aborted.
No captured output, command arguments or environment values are returned.
"""
    if threading.current_thread() is not threading.main_thread():
        raise ValueError('Backup cancellation handling must run on the main thread.')
    process = None
    first_signal = None
    forwarded = False

    def cancel(signum, frame=None):
        nonlocal first_signal, forwarded
        if first_signal is None:
            first_signal = signum
        if process is not None and not forwarded and process.poll() is None:
            forwarded = True
            try:
                process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                # The child won the exit race. The caller still receives the
                # cancelled status and checks whether source writers are stopped.
                pass

    previous = {signum: signal.getsignal(signum)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        for signum in previous:
            signal.signal(signum, cancel)
        process = subprocess.Popen(
            [str(arg) for arg in argv], cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.STDOUT, start_new_session=True)
        if first_signal is not None:
            cancel(first_signal)
        while True:
            try:
                returncode = process.wait()
                break
            except KeyboardInterrupt:
                # Also cover an explicit KeyboardInterrupt from instrumentation
                # or a handler installed by a library while waiting.
                cancel(signal.SIGINT)
        return {'returncode': returncode, 'cancelled': first_signal is not None,
                'signal': first_signal,
                'exitCode': 128 + first_signal if first_signal is not None else returncode}
    finally:
        try:
            if process is not None and process.poll() is None:
                # Unexpected errors must not orphan a backup while it owns a
                # stopped source. Use the same graceful path and await recovery.
                cancel(first_signal or signal.SIGTERM)
                while True:
                    try:
                        process.wait()
                        break
                    except KeyboardInterrupt:
                        cancel(signal.SIGINT)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
