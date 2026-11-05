"""The browser rehearsal must reject production targets before invoking Docker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which('node')
PLAYWRIGHT = ROOT/'tests/browser/node_modules/playwright'


@unittest.skipUnless(NODE and PLAYWRIGHT.is_dir(), 'Node and installed Playwright are required')
class BrowserRehearsalGuardTest(unittest.TestCase):
    def rejected_before_docker(self, **overrides):
        with tempfile.TemporaryDirectory(prefix='migration-browser-guard-') as directory:
            root = Path(directory)/'clone'
            root.mkdir(mode=0o700)
            marker = {'project': 'tm-migrate-test-1234abcd', 'rehearsal': True,
                      'origin': 'https://127.0.0.1:39443', 'targetRoot': str(root)}
            marker.update(overrides)
            (root/'.migration-target.json').write_text(json.dumps(marker))
            bin_dir = Path(directory)/'bin'
            bin_dir.mkdir()
            docker_log = Path(directory)/'docker-was-called'
            docker = bin_dir/'docker'
            docker.write_text('#!/bin/sh\ntouch "'+str(docker_log)+'"\nexit 99\n')
            docker.chmod(0o700)
            environment = dict(os.environ, PATH=str(bin_dir)+os.pathsep+os.environ['PATH'])
            result = subprocess.run([NODE, str(ROOT/'tests/browser/migration-smoke.mjs'),
                                     str(root), str(Path(directory)/'report')],
                                    env=environment, capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Refusing any target except', result.stderr)
            self.assertFalse(docker_log.exists())

    def test_production_marker_is_rejected(self):
        self.rejected_before_docker(rehearsal=False)

    def test_production_project_name_is_rejected(self):
        self.rejected_before_docker(project='team-management')

    def test_non_loopback_destination_is_rejected(self):
        self.rejected_before_docker(origin='https://example.com:39443')

    def test_plain_http_destination_is_rejected(self):
        self.rejected_before_docker(origin='http://127.0.0.1:39443')

    def test_target_directory_mismatch_is_rejected(self):
        self.rejected_before_docker(targetRoot='/not-the-clone')


if __name__ == '__main__':
    unittest.main()
