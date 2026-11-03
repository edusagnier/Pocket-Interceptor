"""Local HTTP and synthetic-input tests; never configure or scan networks."""

import contextlib
import http.client
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lab_portal", ROOT / "tools/lab_portal.py")
portal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portal)


class LabPortalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.journal = portal.DemoJournal(self.temporary.name)
        self.addCleanup(self.journal.close)
        self.nonce = "test-nonce"
        self.server = portal.create_server(self.journal, port=0, nonce=self.nonce)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method="GET", path="/", body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("utf-8")
        finally:
            connection.close()

    def submit(self, **changes):
        fields = dict(account="participante-01", demo_key="DEMO-01", consent="yes", nonce=self.nonce)
        fields.update(changes)
        return self.request("POST", "/submit", urlencode(fields), {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"http://127.0.0.1:{self.server.server_port}",
        })

    def entries(self):
        return self.journal.path.read_text(encoding="utf-8").splitlines()[1:]

    def test_binds_only_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_page_is_explicit_simulation_with_no_freeform_password(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn("SIMULACIÓN EDUCATIVA", body)
        self.assertIn('name="account"', body)
        self.assertNotIn('type="password"', body)
        self.assertNotIn('type="text"', body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_valid_demo_data_is_stored_and_redirects_to_confirmation(self):
        status, headers, _ = self.submit()
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/done")
        self.assertEqual(len(self.entries()), 1)
        self.assertTrue(self.entries()[0].endswith("\tparticipante-01\tDEMO-01"))
        self.assertIn("Participación de prueba registrada", self.request(path="/done")[2])

    def test_each_predefined_pair_is_accepted(self):
        for account, key in portal.DEMO_ACCOUNTS.items():
            self.assertEqual(self.submit(account=account, demo_key=key)[0], 303)
        self.assertEqual(len(self.entries()), len(portal.DEMO_ACCOUNTS))

    def test_arbitrary_credentials_are_rejected_and_not_logged(self):
        value = "PERSONAL_INPUT_MUST_NOT_BE_STORED"
        status, _, body = self.submit(account=value, demo_key=value)
        self.assertEqual(status, 400)
        self.assertEqual(self.entries(), [])
        self.assertNotIn(value, body)
        self.assertNotIn(value, self.journal.path.read_text())

    def test_mismatched_demo_pair_is_rejected(self):
        self.assertEqual(self.submit(demo_key="DEMO-02")[0], 400)
        self.assertEqual(self.entries(), [])

    def test_missing_consent_is_rejected(self):
        self.assertEqual(self.submit(consent="")[0], 400)
        self.assertEqual(self.entries(), [])

    def test_wrong_session_nonce_is_rejected(self):
        self.assertEqual(self.submit(nonce="different-session")[0], 403)
        self.assertEqual(self.submit(nonce="sesión-ajena")[0], 403)
        self.assertEqual(self.entries(), [])

    def test_extra_fields_are_never_stored(self):
        self.assertEqual(self.submit(password="MUST_NOT_BE_STORED")[0], 400)
        self.assertEqual(self.entries(), [])

    def test_duplicate_fields_are_rejected(self):
        body = urlencode(dict(account="participante-01", demo_key="DEMO-01",
                              consent="yes", nonce=self.nonce)) + "&account=participante-02"
        status, _, _ = self.request("POST", "/submit", body, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"http://127.0.0.1:{self.server.server_port}",
        })
        self.assertEqual(status, 400)
        self.assertEqual(self.entries(), [])

    def test_cross_origin_form_is_rejected(self):
        status, _, _ = self.request("POST", "/submit", "account=participante-01", {
            "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://unrelated.invalid",
        })
        self.assertEqual(status, 403)
        self.assertEqual(self.entries(), [])

    def test_unexpected_host_is_rejected(self):
        status, _, _ = self.request(headers={"Host": "unrelated.invalid"})
        self.assertEqual(status, 400)

    def test_excessive_input_is_rejected_before_reading(self):
        status, _, _ = self.request("POST", "/submit", "x" * (portal.MAX_BODY + 1), {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"http://127.0.0.1:{self.server.server_port}",
        })
        self.assertEqual(status, 413)
        self.assertEqual(self.entries(), [])

    def test_no_static_file_or_journal_download(self):
        for path in ("/simulacion.txt", "/../tools/lab_portal.py", "/results", "/creds.txt"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path=path)[0], 404)

    def test_storage_failure_does_not_report_success(self):
        with patch.object(self.journal, "record", side_effect=OSError):
            self.assertEqual(self.submit()[0], 503)
        self.assertEqual(self.entries(), [])

    def test_log_files_have_distinct_names_and_are_preserved(self):
        second = portal.DemoJournal(self.temporary.name)
        second.close()
        self.assertNotEqual(self.journal.path, second.path)
        self.assertTrue(second.path.exists())
        if os.name == "posix":
            self.assertEqual(self.journal.path.stat().st_mode & 0o777, 0o600)

    def test_journal_also_rejects_arbitrary_input_directly(self):
        with self.assertRaises(ValueError):
            self.journal.record("OTHER", "OTHER")
        self.assertEqual(self.entries(), [])

    def test_health_endpoint(self):
        status, _, body = self.request(path="/health")
        self.assertEqual(status, 200)
        self.assertIn('"mode": "simulation"', body)


class LabPortalLifecycleTests(unittest.TestCase):
    def test_ctrl_c_closes_server_and_preserves_results(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_root = Path(directory)
            class InterruptedServer:
                server_port = 8765
                closed = False
                def serve_forever(self, **kwargs):
                    raise KeyboardInterrupt
                def server_close(self):
                    self.closed = True
            server = InterruptedServer()
            with patch.object(portal, "ROOT", fake_root), \
                    patch.object(portal, "create_server", return_value=server), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(portal.main([]), 0)
            self.assertTrue(server.closed)
            self.assertEqual(len(list(fake_root.rglob("simulacion_*.txt"))), 1)

    def test_occupied_port_has_clear_error_and_closes_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch.object(portal, "ROOT", Path(directory)), \
                    patch.object(portal, "create_server", side_effect=OSError), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(portal.main([]), 1)
            self.assertIn("--port 0", output.getvalue())


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH for Bash tests")
class LabPortalMenuTests(unittest.TestCase):
    def launch(self, body):
        executable = os.environ["POCKET_TEST_BASH"]
        env = dict(os.environ, LAB_REPO=ROOT.as_posix())
        env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run([executable, "-c", 'source "$LAB_REPO/lib/lab_portal.sh" || exit 90\n' + body],
                                  cwd=directory, env=env, capture_output=True,
                                  text=True, encoding="utf-8", timeout=10)

    def test_menu_invokes_python_with_absolute_path(self):
        result = self.launch('python3() { [[ "$1" == -B && "$2" == "$LAB_PORTAL_DIRECTORY/tools/lab_portal.py" ]]; }; run_lab_portal')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_python_is_reported(self):
        result = self.launch('command() { return 1; }; run_lab_portal')
        self.assertEqual(result.returncode, 127)
        self.assertIn("Python 3", result.stderr)

    def test_execution_error_preserves_status(self):
        result = self.launch('python3() { return 7; }; run_lab_portal')
        self.assertEqual(result.returncode, 7)
        self.assertIn("código 7", result.stderr)


if __name__ == "__main__":
    unittest.main()
