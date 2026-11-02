"""Run with: python3 -B -m unittest discover -s tests -v.

No system services, firewall commands or network tools are executed.
Set POCKET_TEST_BASH to a Bash executable to include shell lifecycle tests.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("session_state", ROOT / "tools/session_state.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeHost:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.forwarding = "1"
        self.interface_up = True
        self.interface_type = "managed"
        self.firewall = "*nat\nCOMMIT\n*filter\nCOMMIT\n"
        self.services = {service: "inactive" for service in MODULE.SERVICES}
        self.services["NetworkManager"] = "active"

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.fail == args:
            raise subprocess.CalledProcessError(1, args)
        output = b""
        if args[:2] == ("systemctl", "show"):
            output = self.services[args[2]].encode()
        elif args[:2] == ("sysctl", "-n"):
            output = self.forwarding.encode()
        elif args[:3] == ("ip", "-j", "link"):
            output = json.dumps([{"flags": ["UP"] if self.interface_up else []}]).encode()
        elif args[:2] == ("iw", "dev") and args[-1] == "info":
            output = f"Interface wlan0\n\ttype {self.interface_type}\n".encode()
        elif args[:3] == ("ip", "address", "save"):
            output = b"original-addresses"
        elif args[:3] == ("ip", "route", "save"):
            output = b"original-routes"
        elif args[:4] == ("ip", "-6", "route", "save"):
            output = b"original-ipv6-routes"
        elif args == ("iptables-save",):
            output = self.firewall.encode()
        return subprocess.CompletedProcess(args, 0, stdout=output, stderr=b"")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.directory = self.base / "session"
        self.directory.mkdir()
        self.config = self.base / "config.conf"
        self.config.write_text("original configuration", encoding="utf-8")
        self.newfile = self.base / "created.php"
        self.otherfile = self.base / "unrelated.txt"
        self.otherfile.write_text("keep", encoding="utf-8")
        self.host = FakeHost()
        self.session = MODULE.Session(self.directory, runner=self.host)

    def begin(self):
        return self.session.begin("wlan0", paths=(self.config, self.newfile), link_dirs=())

    def commands(self):
        return [args for args, _ in self.host.calls]

    def test_snapshot_only_reads_host_state(self):
        state = self.begin()
        self.assertEqual(state["forwarding"], "1")
        self.assertTrue(state["interface_up"])
        self.assertFalse(any("stop" in args or "-w" in args for args in self.commands()))

    def test_missing_interface_aborts_before_any_mutation(self):
        self.host.fail = ("iw", "dev", "wlan0", "info")
        with self.assertRaises(subprocess.CalledProcessError):
            self.begin()
        self.assertFalse((self.directory / "state.json").exists())
        self.assertFalse(any("stop" in args for args in self.commands()))

    def test_unstable_service_aborts_snapshot(self):
        self.host.services["apache2"] = "activating"
        with self.assertRaises(ValueError):
            self.begin()

    def test_unknown_forwarding_aborts_snapshot(self):
        self.host.forwarding = "unknown"
        with self.assertRaises(ValueError):
            self.begin()

    def test_restores_original_files_and_removes_only_created_files(self):
        self.begin()
        self.config.write_text("session configuration", encoding="utf-8")
        self.newfile.write_text("session PHP", encoding="utf-8")
        self.assertEqual(self.session.finish(), [])
        self.assertEqual(self.config.read_text(), "original configuration")
        self.assertFalse(self.newfile.exists())
        self.assertEqual(self.otherfile.read_text(), "keep")

    def test_cleanup_is_idempotent(self):
        self.begin()
        self.assertEqual(self.session.finish(), [])
        before = len(self.host.calls)
        self.assertEqual(self.session.finish(), [])
        self.assertEqual(len(self.host.calls), before)

    def test_restores_only_touched_services_to_prior_active_state(self):
        self.begin()
        self.session.service("stop", "NetworkManager")
        self.session.service("restart", "apache2")
        self.host.calls.clear()
        self.session.finish()
        calls = self.commands()
        self.assertIn(("systemctl", "start", "NetworkManager"), calls)
        self.assertIn(("systemctl", "stop", "apache2"), calls)
        self.assertNotIn(("systemctl", "start", "apache2"), calls)
        self.assertFalse(any("dnsmasq" in args for args in calls))

    def test_failed_service_change_is_journaled_before_execution(self):
        self.begin()
        self.host.fail = ("systemctl", "restart", "apache2")
        with self.assertRaises(subprocess.CalledProcessError):
            self.session.service("restart", "apache2")
        self.assertIn("apache2", self.session.load()["touched_services"])

    def test_restores_original_forwarding_instead_of_forcing_zero(self):
        self.begin()
        self.session.mark("forwarding_dirty")
        self.session.finish()
        self.assertIn(("sysctl", "-w", "net.ipv4.ip_forward=1"), self.commands())

    def test_untouched_interface_and_forwarding_are_not_modified(self):
        self.begin()
        self.host.calls.clear()
        self.session.finish()
        self.assertFalse(any(args[0] in ("ip", "iw", "sysctl") for args in self.commands()))

    def test_restores_interface_type_link_addresses_and_routes(self):
        self.begin()
        self.session.mark("interface_dirty")
        self.session.finish()
        self.assertIn(("iw", "dev", "wlan0", "set", "type", "managed"), self.commands())
        self.assertIn(("ip", "link", "set", "wlan0", "up"), self.commands())
        restored = {args: kwargs.get("input") for args, kwargs in self.host.calls}
        self.assertEqual(restored[("ip", "address", "restore")], b"original-addresses")
        self.assertEqual(restored[("ip", "route", "restore")], b"original-routes")
        self.assertEqual(restored[("ip", "-6", "route", "restore")], b"original-ipv6-routes")

    def test_restores_an_initially_down_monitor_interface(self):
        self.host.interface_up = False
        self.host.interface_type = "monitor"
        self.begin()
        self.session.mark("interface_dirty")
        self.session.finish()
        self.assertIn(("iw", "dev", "wlan0", "set", "type", "monitor"), self.commands())
        self.assertEqual([args for args in self.commands() if args[:3] == ("ip", "link", "set")][-1],
                         ("ip", "link", "set", "wlan0", "down"))

    def test_firewall_cleanup_matches_full_tag_and_preserves_unrelated_rules(self):
        state = self.begin()
        tag = state["tag"]
        self.host.firewall = (
            '*filter\n-A FORWARD -s 192.0.2.1 -j ACCEPT\n'
            f'-A FORWARD -m comment --comment "{tag}-other" -j ACCEPT\n'
            f'-A FORWARD -m comment --comment "{tag}" -j REJECT\nCOMMIT\n'
            f'*nat\n-A PREROUTING -m comment --comment {tag} -j RETURN\nCOMMIT\n'
        )
        self.session.finish()
        deletions = [args for args in self.commands() if args[0] == "iptables"]
        self.assertEqual(len(deletions), 2)
        self.assertTrue(all(tag in args and "-D" in args for args in deletions))
        self.assertFalse(any("-F" in args for args in self.commands()))

    def test_rule_additions_receive_session_tag(self):
        state = self.begin()
        self.session.iptables(["-A", "FORWARD", "-j", "ACCEPT"])
        self.assertEqual(self.commands()[-1][-4:], ("-m", "comment", "--comment", state["tag"]))

    def test_one_failed_restore_does_not_skip_other_recovery_and_can_retry(self):
        self.begin()
        self.session.service("stop", "NetworkManager")
        self.session.mark("forwarding_dirty")
        self.host.fail = ("sysctl", "-w", "net.ipv4.ip_forward=1")
        self.assertTrue(self.session.finish())
        self.assertIn(("systemctl", "start", "NetworkManager"), self.commands())
        self.assertFalse(self.session.load()["finished"])
        self.host.fail = None
        self.assertEqual(self.session.finish(), [])

    def test_recovery_refuses_unexpected_directory(self):
        self.begin()
        self.newfile.mkdir()
        self.assertTrue(self.session.finish())
        self.assertTrue(self.newfile.is_dir())

    def test_rejects_unscoped_firewall_and_service_operations(self):
        self.begin()
        with self.assertRaises(ValueError):
            self.session.iptables(["-F"])
        with self.assertRaises(ValueError):
            self.session.service("stop", "unrelated-service")


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH for Bash lifecycle tests")
class ShellTests(unittest.TestCase):
    def run_shell(self, action, cleanup_status=0):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "calls.txt"
            # Replace only the helper boundary: no Linux administration command runs.
            script = r'''
source lib/session.sh || exit 90
SESSION_DIRECTORY="test-session"
session_command() { printf '%s\n' "$1" >> "$TEST_LOG"; return "$TEST_CLEANUP_STATUS"; }
session_register_traps
'''+action
            env = dict(os.environ, TEST_LOG=log.as_posix(), TEST_CLEANUP_STATUS=str(cleanup_status))
            # Embedded Git Bash is not necessarily on the Windows host's PATH.
            env["PATH"] = str(Path(os.environ["POCKET_TEST_BASH"]).parent) + os.pathsep + env.get("PATH", "")
            result = subprocess.run([os.environ["POCKET_TEST_BASH"], "-c", script],
                                    cwd=ROOT, env=env, capture_output=True, timeout=15)
            calls = log.read_text().splitlines() if log.exists() else []
            return result.returncode, calls, result.stderr.decode(errors="replace")

    def test_normal_exit(self):
        code, calls, _ = self.run_shell("exit 0")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["finish"])

    def test_failure_preserves_exit_status(self):
        code, calls, _ = self.run_shell("exit 7")
        self.assertEqual(code, 7)
        self.assertEqual(calls, ["finish"])

    def test_interrupts_run_cleanup_and_preserve_signal_status(self):
        for signal, expected in (("INT", 130), ("TERM", 143), ("HUP", 129)):
            with self.subTest(signal=signal):
                code, calls, _ = self.run_shell('kill -'+signal+' "$BASHPID"')
                self.assertEqual(code, expected)
                self.assertEqual(calls, ["finish"])

    def test_cleanup_failure_makes_successful_exit_fail(self):
        code, calls, stderr = self.run_shell("exit 0", cleanup_status=1)
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["finish"])
        self.assertIn("test-session", stderr)

    def test_explicit_cleanup_does_not_run_again_at_exit(self):
        code, calls, _ = self.run_shell("session_cleanup; exit 0")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["finish"])

    def test_subshell_return_runs_cleanup(self):
        # Register the EXIT trap inside the subshell, as the portal does.
        code, calls, _ = self.run_shell(
            "trap - EXIT; portal() ( session_register_traps; return 0; ); portal; exit 0")
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["finish"])

    def test_cleanup_failure_does_not_hide_original_error(self):
        code, calls, _ = self.run_shell("exit 7", cleanup_status=1)
        self.assertEqual(code, 7)
        self.assertEqual(calls, ["finish"])

    def test_temporary_php_is_stamped_with_private_result_path(self):
        code, calls, stderr = self.run_shell(r'''
SESSION_DIRECTORY="$TEST_LOG.work"
DIRECTORY="$SESSION_DIRECTORY/generated/"
mkdir -p "$DIRECTORY"
SESSION_TAG=pocket-test
FILE_REGISTER=register.php
FILE_LINKEDIN=linkedin.php
FILE_MICROSOFT=microsoft.php
printf '%s' '__POCKET_SESSION_TAG__:__POCKET_RESULTS_FILE__' > "${DIRECTORY}${FILE_REGISTER}"
session_prepare_web_files || exit 8
content=$(cat "${DIRECTORY}${FILE_REGISTER}")
[[ "$content" == "pocket-test:$SESSION_DIRECTORY/results/credentials.log" ]] || {
    printf 'Actual: %q\nExpected: %q\n' "$content" "pocket-test:$SESSION_DIRECTORY/results/credentials.log" >&2
    exit 9
}
''')
        self.assertEqual(code, 0, stderr)
        self.assertEqual(calls, ["finish"])

    def test_foreground_process_failure_is_preserved(self):
        code, calls, _ = self.run_shell('session_run_foreground "$POCKET_TEST_BASH" -c "exit 9"; exit $?')
        self.assertEqual(code, 9)
        self.assertEqual(calls, ["finish"])

    def test_cleanup_signals_only_the_tracked_child(self):
        code, calls, _ = self.run_shell(r'''
SESSION_CHILD_PID=123
kill() { printf '%s\n' "kill:$*" >> "$TEST_LOG"; return 1; }
wait() { printf '%s\n' "wait:$*" >> "$TEST_LOG"; return 0; }
exit 0
''')
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["kill:-TERM 123", "kill:-0 123", "kill:-KILL 123", "wait:123", "finish"])


if __name__ == "__main__":
    unittest.main()
