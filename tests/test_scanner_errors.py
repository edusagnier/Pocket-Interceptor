"""Scanner diagnostics: all external commands and HTTP calls are simulated."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("scanner", ROOT / "netscan.py")
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class ScannerErrors(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_missing_nmap_has_actionable_error(self):
        with patch.object(scanner.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(scanner.ScanError, "No se encuentra nmap"):
                scanner.devscan("192.0.2.1")

    def test_invalid_addresses_never_execute_a_command(self):
        with patch.object(scanner.subprocess, "run") as run:
            for address in ("999.999.999.999", "192.0.2.0/99", "--help"):
                with self.subTest(address=address), self.assertRaises(scanner.ScanError):
                    scanner.netscan(address)
            run.assert_not_called()

    def test_timeout_is_not_an_empty_result(self):
        with patch.object(scanner.subprocess, "run", side_effect=subprocess.TimeoutExpired("nmap", 1800)):
            with self.assertRaisesRegex(scanner.ScanError, "30 minutos"):
                scanner.devscan("192.0.2.1")

    def test_permission_error_is_clear(self):
        with patch.object(scanner.subprocess, "run", side_effect=PermissionError):
            with self.assertRaisesRegex(scanner.ScanError, "permiso"):
                scanner.devscan("192.0.2.1")

    def test_nonzero_exit_reports_status_and_bounded_sanitized_detail(self):
        failure = subprocess.CalledProcessError(2, ["nmap"], stderr="\x1b[31mpermission denied\n" + "x" * 2000)
        with patch.object(scanner.subprocess, "run", side_effect=failure):
            with self.assertRaises(scanner.ScanError) as caught:
                scanner.devscan("192.0.2.1")
        message = str(caught.exception)
        self.assertIn("2", message)
        self.assertIn("permission denied", message)
        self.assertNotIn("\x1b", message)
        self.assertLess(len(message), 1100)

    def test_empty_stdout_is_not_reported_as_no_devices(self):
        result = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch.object(scanner.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(scanner.ScanError, "sin salida"):
                scanner.devscan("192.0.2.1")

    def test_normal_scan_preserves_existing_parser_behavior(self):
        result = subprocess.CompletedProcess([], 0, stdout=(
            "Nmap scan report for 192.0.2.1\n22/tcp open ssh OpenSSH 9.6p1\n"), stderr="")
        with patch.object(scanner.subprocess, "run", return_value=result) as run:
            self.assertEqual(scanner.devscan("192.0.2.1"), {"192.0.2.1": [("22", "ssh", "9.6p1")]})
            self.assertTrue(run.call_args.kwargs["check"])

    def test_missing_requests_disables_only_cve_queries(self):
        with patch.object(scanner, "requests", None):
            self.assertIsNone(scanner.check_cve_nvd("ssh", "9.6"))
        self.assertIn("requests", self.output.getvalue())

    def test_failed_cve_query_never_claims_no_vulnerabilities(self):
        with patch.object(scanner, "check_cve_nvd", return_value=None):
            scanner.results({"192.0.2.1": [("22", "ssh", "9.6")]})
        self.assertIn("desconocido", self.output.getvalue())
        self.assertNotIn("Sin coincidencias", self.output.getvalue())

    def test_empty_cve_query_is_explicitly_inconclusive(self):
        with patch.object(scanner, "check_cve_nvd", return_value=[]):
            scanner.results({"192.0.2.1": [("22", "ssh", "9.6")]})
        self.assertIn("no confirma ausencia", self.output.getvalue())

    def test_api_error_does_not_print_exception_secrets(self):
        class RequestError(Exception):
            pass
        error = RequestError("PRIVATE_KEY_MUST_NOT_APPEAR")
        error.response = SimpleNamespace(status_code=429)
        fake = SimpleNamespace(exceptions=SimpleNamespace(RequestException=RequestError),
                               get=Mock(side_effect=error))
        with patch.object(scanner, "requests", fake), patch.object(scanner, "sleep"):
            self.assertIsNone(scanner.check_cve_nvd("ssh", "9.6"))
        self.assertIn("429", self.output.getvalue())
        self.assertNotIn("PRIVATE_KEY_MUST_NOT_APPEAR", self.output.getvalue())

    def test_unparsed_results_do_not_claim_an_empty_network(self):
        scanner.results({})
        self.assertIn("parser", self.output.getvalue())

    def test_discovery_uses_project_directory_and_reports_failure(self):
        with patch.object(scanner.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["bash"])) as run:
            with self.assertRaisesRegex(scanner.ScanError, "código 1"):
                scanner.netdisc()
        self.assertEqual(run.call_args.kwargs["cwd"], scanner.SCRIPT_DIRECTORY)
        self.assertTrue(Path(run.call_args.args[0][1]).is_absolute())

    def test_menu_recovers_after_expected_failure(self):
        with patch("builtins.input", side_effect=["2", "192.0.2.1", "0"]), \
                patch.object(scanner, "devscan", side_effect=scanner.ScanError("simulated error")):
            with self.assertRaises(SystemExit) as caught:
                scanner.menu()
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("[ERROR] simulated error", self.output.getvalue())


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH for Bash tests")
class ScannerLauncher(unittest.TestCase):
    def launch(self, body):
        executable = os.environ["POCKET_TEST_BASH"]
        env = dict(os.environ, SCANNER_REPO=ROOT.as_posix())
        env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run([executable, "-c", 'source "$SCANNER_REPO/lib/scanner.sh" || exit 90\n' + body],
                                  cwd=directory, env=env, capture_output=True, text=True,
                                  encoding="utf-8", timeout=10)

    def test_launcher_survives_another_working_directory(self):
        result = self.launch('python3() { [[ "$1" == "$SCANNER_DIRECTORY/netscan.py" ]]; }; run_network_scanner')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_launcher_reports_and_preserves_exit_code(self):
        result = self.launch('python3() { return 7; }; run_network_scanner')
        self.assertEqual(result.returncode, 7)
        self.assertIn("código 7", result.stderr)

    def test_launcher_reports_missing_python(self):
        result = self.launch('command() { return 1; }; run_network_scanner')
        self.assertEqual(result.returncode, 127)
        self.assertIn("python3", result.stderr)


if __name__ == "__main__":
    unittest.main()
