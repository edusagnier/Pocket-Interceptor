"""Passive discovery UI tests; timeout and airodump-ng are never executed."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH for Bash tests")
class WirelessDiscoveryTests(unittest.TestCase):
    def run_scan(self, status=124, create_csv=True, missing_tool="", interface="wlan0mon"):
        executable = os.environ["POCKET_TEST_BASH"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output with spaces"
            output.mkdir()
            # A failed scan must not reuse an older result.
            (output / "networks-01.csv").write_text("STALE_RESULT")
            env = dict(os.environ, WIRELESS_REPO=ROOT.as_posix(), WIRELESS_OUTPUT=output.as_posix(),
                       FAKE_STATUS=str(status), FAKE_CSV="yes" if create_csv else "no",
                       FAKE_MISSING=missing_tool, FAKE_INTERFACE=interface)
            env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
            body = r'''
set +o posix
source "$WIRELESS_REPO/lib/wireless_scan.sh" || exit 90
command() {
    if [[ "$1" == -v && "$2" == "$FAKE_MISSING" ]]; then return 1; fi
    if [[ "$1" == -v && ( "$2" == airodump-ng || "$2" == timeout ) ]]; then return 0; fi
    builtin command "$@"
}
timeout() {
    local prefix="" arg expect_prefix=no
    for arg in "$@"; do
        if [[ "$expect_prefix" == yes ]]; then prefix=$arg; expect_prefix=no; fi
        if [[ "$arg" == -w ]]; then expect_prefix=yes; fi
        printf 'ARG=%s\n' "$arg"
    done
    if [[ "$FAKE_CSV" == yes ]]; then printf 'SIMULATED_CSV\n' > "${prefix}-01.csv"; fi
    return "$FAKE_STATUS"
}
x-terminal-emulator() { printf GUI_MUST_NOT_RUN; return 91; }
wmctrl() { printf GUI_MUST_NOT_RUN; return 91; }
scan_wireless_networks "$FAKE_INTERFACE" "$WIRELESS_OUTPUT"
status=$?
printf 'RESULT=%s\n' "$WIRELESS_SCAN_FILE"
if [[ -n "$WIRELESS_SCAN_FILE" ]]; then cat "$WIRELESS_SCAN_FILE"; fi
exit "$status"
'''
            result = subprocess.run([executable, "-c", body], cwd=directory, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=10)
            self.assertNotIn("GUI_MUST_NOT_RUN", result.stdout)
            return result

    def test_expected_timeout_uses_new_csv_without_gui(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SIMULATED_CSV", result.stdout)
        self.assertIn("/discovery_", result.stdout)
        self.assertNotIn("STALE_RESULT", result.stdout)

    def test_normal_exit_is_accepted(self):
        result = self.run_scan(status=0)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tool_failure_is_not_reported_as_a_success(self):
        result = self.run_scan(status=2)
        self.assertEqual(result.returncode, 2)
        self.assertIn("código 2", result.stderr)
        self.assertIn("RESULT=\n", result.stdout)

    def test_missing_csv_does_not_reuse_previous_scan(self):
        result = self.run_scan(create_csv=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("CSV", result.stderr)
        self.assertNotIn("STALE_RESULT", result.stdout)

    def test_interrupt_is_reported_as_cancellation(self):
        result = self.run_scan(status=130)
        self.assertEqual(result.returncode, 130)
        self.assertIn("cancelado", result.stderr)

    def test_missing_dependencies_are_reported(self):
        for tool in ("airodump-ng", "timeout"):
            with self.subTest(tool=tool):
                result = self.run_scan(missing_tool=tool)
                self.assertEqual(result.returncode, 127)
                self.assertIn(tool, result.stderr)
                self.assertNotIn("ARG=", result.stdout)

    def test_no_interface_never_starts_a_scan(self):
        result = self.run_scan(interface="")
        self.assertEqual(result.returncode, 1)
        self.assertIn("interfaz", result.stderr)
        self.assertNotIn("ARG=", result.stdout)

    def test_interface_is_passed_as_one_argument(self):
        result = self.run_scan(interface="literal interface; text")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARG=literal interface; text\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
