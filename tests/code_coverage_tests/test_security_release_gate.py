"""Exercise the deployment gate as a process against real report files."""
import json
import pathlib
import subprocess
import tempfile
import unittest

GATE = pathlib.Path(__file__).resolve().parents[2] / 'scripts/gate-container-vulnerabilities.sh'


class ReleaseGateTests(unittest.TestCase):
    def test_report_results(self):
        cases = [
            ({'scan': {'status': 'success'}, 'vulnerabilities': []}, True),
            ({'scan': {'status': 'success'}, 'vulnerabilities': [{'severity': 'Medium'}]}, True),
            ({'scan': {'status': 'success'}, 'vulnerabilities': [{'severity': 'High'}]}, False),
            ({'scan': {'status': 'success'}, 'vulnerabilities': [{'severity': 'Critical', 'solution': ''}]}, False),
            ({'scan': {'status': 'success'}, 'vulnerabilities': [{'severity': 'High', 'solution': 'upgrade'}]}, False),
            ({'scan': {'status': 'failure'}, 'vulnerabilities': []}, False),
            ({'scan': {'status': 'success'}}, False),
            ({'vulnerabilities': []}, False),
            ({'scan': {'status': 'success'}, 'vulnerabilities': [{'severity': 'high'}]}, False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            clean = root / 'clean.json'
            clean.write_text(json.dumps({'scan': {'status': 'success'}, 'vulnerabilities': []}))
            for report, allowed in cases:
                with self.subTest(report=report):
                    candidate = root / 'candidate.json'
                    candidate.write_text(json.dumps(report))
                    result = subprocess.run(['bash', str(GATE), str(clean), str(candidate)], capture_output=True)
                    self.assertEqual(result.returncode == 0, allowed)

    def test_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            malformed = root / 'malformed.json'
            malformed.write_text('{incomplete')
            for arguments in ([], [str(root / 'absent.json')], [str(malformed)]):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(['bash', str(GATE), *arguments], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
