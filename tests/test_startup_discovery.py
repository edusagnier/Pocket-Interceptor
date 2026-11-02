"""Run the complete menu with a pre-existing wireless mode and synthetic CSV."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH")
class StartupDiscoveryTests(unittest.TestCase):
    def program(self, interface="wlan0mon", mode="monitor", view="inline", gui_failure=False,
                scan_status=124):
        executable = os.environ["POCKET_TEST_BASH"]
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            shutil.copyfile(ROOT / "interceptor.sh", fixture / "interceptor.sh")
            shutil.copytree(ROOT / "lib", fixture / "lib")
            (fixture / "tools").mkdir()
            shutil.copyfile(ROOT / "tools/session_state.py", fixture / "tools/session_state.py")
            env = dict(os.environ, STARTUP_FIXTURE=fixture.as_posix(), FAKE_INTERFACE=interface,
                       FAKE_MODE=mode, FAKE_GUI_FAIL=str(int(gui_failure)),
                       FAKE_SCAN_STATUS=str(scan_status),
                       POCKET_TERMINAL_MODE=view, DISPLAY=":synthetic", WAYLAND_DISPLAY="", TMUX="")
            env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
            script = r'''
id() { printf '0\n'; }
clear() { :; }
sleep() { if [[ $1 == 0.1 ]]; then command sleep "$@"; fi; }
sudo() { printf 'UNEXPECTED_SYSTEM_CHANGE %s\n' "$*" >&2; return 90; }
ip() {
    if [[ "$*" == '-o link show' ]]; then
        printf '3: %s: <BROADCAST,MULTICAST,UP> mtu 1500 state UNKNOWN\n' "$FAKE_INTERFACE"
    else
        printf 'UNEXPECTED_LINK_CHANGE %s\n' "$*" >&2
        return 90
    fi
}
iw() {
    if [[ $1 == list ]]; then
        printf 'Wiphy phy0\n\tBand 1:\n\t\t2412 MHz\n'
    elif [[ "$*" == "dev $FAKE_INTERFACE info" ]]; then
        printf 'Interface %s\n\twiphy 0\n\ttype %s\n' "$FAKE_INTERFACE" "$FAKE_MODE"
    else
        return 1
    fi
}
iwconfig() {
    [[ $1 == "$FAKE_INTERFACE" ]] || return 1
    if [[ $FAKE_MODE == monitor ]]; then
        printf '%s IEEE 802.11 Mode:Monitor\n' "$1"
    else
        printf '%s IEEE 802.11 Mode:Managed\n' "$1"
    fi
}
airmon-ng() { printf 'UNEXPECTED_AIRMON %s\n' "$*" >&2; return 90; }
command() {
    if [[ $1 == -v && $2 == airodump-ng ]]; then return 0; fi
    builtin command "$@"
}
timeout() {
    printf '[SIMULATED SCAN] interface=%s\n' "${@: -4:1}"
    if [[ $FAKE_SCAN_STATUS == 1 ]]; then
        printf 'ioctl(SIOCSIFFLAGS) failed: Protocol error\nFailed initializing wireless card(s): wlan0mon\n' >&2
        return 1
    fi
    local prefix=""
    while [[ $# -gt 0 ]]; do
        if [[ $1 == -w ]]; then prefix=$2; break; fi
        shift
    done
    [[ -n $prefix ]] || return 91
    printf 'BSSID,First seen,Last seen,Channel,Speed,Privacy,Cipher,Authentication,Power,Beacons,IV,LAN IP,ID length,ESSID,Key\n' > "${prefix}-01.csv"
    printf '02:00:00:00:00:01,first,last,6,54,WPA2,CCMP,PSK,-40,10,0,0.0.0.0,8,LAB_TEST,\n' >> "${prefix}-01.csv"
    return 124
}
gnome-terminal() {
    [[ $FAKE_GUI_FAIL == 0 ]] || return 1
    printf '[SIMULATED WINDOW] Pocket: redes\n'
    while [[ $1 != -- ]]; do shift; done
    shift
    "$@"
}
export -f timeout
source "$STARTUP_FIXTURE/interceptor.sh"
'''
            inputs = "1\n4\n0\nn\n0\n" if mode == "monitor" and scan_status == 124 else "1\n4\n0\n"
            result = subprocess.run([executable, "-c", script], env=env, cwd=directory,
                                    input=inputs.encode("utf-8"), capture_output=True, timeout=15)
            result.stdout = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout.decode("utf-8"))
            result.stderr = result.stderr.decode("utf-8")
            return result

    def assert_monitor_startup(self, result, interface):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"{interface}  in Mode: Monitor", result.stdout)
        self.assertIn("Buscando redes durante 10 segundos", result.stdout)
        self.assertIn(f"[SIMULATED SCAN] interface={interface}", result.stdout)
        self.assertRegex(result.stdout, r"0\s+02:00:00:00:00:01\s+LAB_TEST")
        self.assertIn("You have the wireless network LAB_TEST selected", result.stdout)
        self.assertNotIn("Invalid ID", result.stdout)
        self.assertNotIn("Not in monitor mode", result.stdout)
        self.assertNotIn("UNEXPECTED_", result.stdout + result.stderr)

    def test_preexisting_monitor_is_detected_and_first_network_can_be_selected(self):
        self.assert_monitor_startup(self.program(), "wlan0mon")

    def test_preexisting_monitor_without_suffix_is_detected(self):
        self.assert_monitor_startup(self.program(interface="wlan0"), "wlan0")

    def test_managed_interface_with_mon_suffix_is_not_misidentified(self):
        result = self.program(mode="managed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("in Mode: Managed", result.stdout)
        self.assertIn("Not in monitor mode", result.stdout)
        self.assertNotIn("SIMULATED SCAN", result.stdout)
        self.assertNotIn("UNEXPECTED_", result.stdout + result.stderr)

    def test_preexisting_monitor_opens_separate_view(self):
        result = self.program(view="auto")
        self.assert_monitor_startup(result, "wlan0mon")
        self.assertIn("[SIMULATED WINDOW] Pocket: redes", result.stdout)

    def test_preexisting_monitor_uses_inline_fallback_when_window_fails(self):
        result = self.program(view="auto", gui_failure=True)
        self.assert_monitor_startup(result, "wlan0mon")
        self.assertIn("continuando en esta terminal", result.stderr)

    def test_scanner_error_survives_the_separate_window_closing(self):
        result = self.program(view="auto", scan_status=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[SIMULATED WINDOW]", result.stdout)
        self.assertIn("ioctl(SIOCSIFFLAGS) failed: Protocol error", result.stderr)
        self.assertIn("Failed initializing wireless card(s): wlan0mon", result.stderr)
        self.assertIn("código 1", result.stderr)
        self.assertIn("scan.stderr.log", result.stderr)
        self.assertNotIn("Selected complete information", result.stdout)
