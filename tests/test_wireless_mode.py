"""Exercise menu mode transitions with synthetic iw/airmon responses."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH")
class WirelessModeTests(unittest.TestCase):
    def mode(self, initial="monitor", operation="monitor_mode", link_status=0):
        executable = os.environ["POCKET_TEST_BASH"]
        source = (ROOT / "interceptor.sh").read_text(encoding="utf-8")
        functions = "monitor_mode(){" + source.split("monitor_mode(){", 1)[1].split("check_password(){", 1)[0]
        env = dict(os.environ, FAKE_MODE=initial, FAKE_LINK_STATUS=str(link_status))
        env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
        setup = r'''
SELECTED_INTERFACE=wlan0
MON_INTERFACE=wlan0
sudo() { "$@"; }
sleep() { :; }
service() { :; }
iwconfig() { :; }
ip() { printf 'LINK %s\n' "$*"; return "$FAKE_LINK_STATUS"; }
airmon-ng() {
    printf 'AIRMON %s\n' "$*"
    case "$1" in start) FAKE_MODE=monitor ;; stop) FAKE_MODE=managed ;; esac
}
iw() {
    if [[ $# == 1 ]]; then
        printf 'phy#9\n\tInterface othermon\nphy#0\n\tInterface wlan0\n'
    elif [[ $2 == othermon ]]; then
        printf 'Interface othermon\n\twiphy 9\n\ttype monitor\n'
    else
        printf 'Interface wlan0\n\twiphy 0\n\ttype %s\n' "$FAKE_MODE"
    fi
}
'''
        body = setup + functions + '\n' + operation + r'''
status=$?
printf 'STATUS=%s MON=%s SELECTED=%s\n' "$status" "$MON_INTERFACE" "$SELECTED_INTERFACE"
exit "$status"
'''
        return subprocess.run([executable, "-c", body], env=env, capture_output=True,
                              text=True, encoding="utf-8", timeout=10)

    def test_existing_monitor_without_suffix_is_refreshed_on_same_adapter(self):
        result = self.mode()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MON=wlan0", result.stdout)
        self.assertIn("LINK link set dev wlan0 down", result.stdout)
        self.assertIn("LINK link set dev wlan0 up", result.stdout)
        self.assertNotIn("AIRMON start", result.stdout)

    def test_managed_interface_is_activated_and_actual_name_is_used(self):
        result = self.mode(initial="managed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AIRMON start wlan0", result.stdout)
        self.assertIn("MON=wlan0", result.stdout)

    def test_driver_failure_is_returned_to_menu(self):
        result = self.mode(link_status=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("STATUS=1", result.stdout)
        self.assertNotIn("[OK]", result.stdout)

    def test_manager_transition_accepts_monitor_without_suffix(self):
        result = self.mode(operation="manager_mode")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AIRMON stop wlan0", result.stdout)
        self.assertIn("MON= SELECTED=wlan0", result.stdout)
