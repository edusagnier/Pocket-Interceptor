"""Presentation tests only, with synthetic files and simulated commands."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH for Bash tests")
class LiveOutputTests(unittest.TestCase):
    def run_view(self, body, fixture=True):
        executable = os.environ["POCKET_TEST_BASH"]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            if fixture:
                (folder / "input.cap").write_text("synthetic input, not a handshake")
                (folder / "words.txt").write_text("synthetic word")
            env = dict(os.environ, VIEW_REPO=ROOT.as_posix(), VIEW_TMP=folder.as_posix(),
                       POCKET_TERMINAL_MODE="inline")
            env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
            setup = r'''
source "$VIEW_REPO/lib/live_output.sh" || exit 90
script() {
    local command_line logfile status
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --command) command_line=$2; shift 2 ;;
            --quiet|--return|--flush) shift ;;
            *) logfile=$1; shift ;;
        esac
    done
    if [[ "$command_line" == exec\ aircrack-ng\ * ]]; then
        printf '%s\n' "$VIEW_OUTPUT" > "$logfile"
        status=$VIEW_STATUS
    else
        "$SHELL" -c "$command_line" > "$logfile" 2>&1
        status=$?
    fi
    cat "$logfile"
    return "$status"
}
command() {
    if [[ "$1" == -v && "$2" == aircrack-ng ]]; then return 0; fi
    builtin command "$@"
}
VIEW_OUTPUT=$'SIMULATED PROGRESS\nKEY FOUND! [SIMULATED_MATCH]'
VIEW_STATUS=0
export VIEW_OUTPUT VIEW_STATUS
export -f script
'''
            result = subprocess.run([executable, "-c", setup + body], cwd=directory,
                                    env=env, capture_output=True, text=True,
                                    encoding="utf-8", timeout=15)
            logs = [p.read_text(encoding="utf-8") for p in folder.glob("result_handshake_*.txt")]
            return result, logs, (folder / "input.cap").exists()

    def test_progress_is_visible_and_saved_without_deleting_capture(self):
        result, logs, capture_exists = self.run_view(
            'show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SIMULATED PROGRESS", result.stdout)
        self.assertEqual(len(logs), 1)
        self.assertIn("SIMULATED PROGRESS", logs[0])
        self.assertTrue(capture_exists)
        self.assertIn("Contraseña encontrada", result.stdout)
        self.assertIn("KEY FOUND! [SIMULATED_MATCH]", result.stdout)

    def test_results_are_named_by_essid_and_previous_runs_are_preserved(self):
        result, _, capture_exists = self.run_view(r'''
for attempt in 1 2; do
    show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP" 'Mi Wifi' || exit $?
done
count=0
for logfile in "$VIEW_TMP"/analysis_*/'results_Mi Wifi_handshake_'*.txt; do
    [[ -f "$logfile" ]] || exit 91
    grep -Fq 'SIMULATED PROGRESS' "$logfile" || exit 92
    count=$((count + 1))
done
printf 'NETWORK_RESULTS=%s\n' "$count"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NETWORK_RESULTS=2", result.stdout)
        self.assertIn("Red analizada (ESSID): Mi Wifi", result.stdout)
        capture_id = hashlib.sha256(b"synthetic input, not a handshake").hexdigest()[:12]
        self.assertIn(f"results_Mi Wifi_handshake_{capture_id}.txt", result.stdout)
        self.assertTrue(capture_exists)

    def test_essid_path_separators_are_sanitized(self):
        result, logs, _ = self.run_view(r'''
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP" 'My/Wifi:Test' || exit $?
for logfile in "$VIEW_TMP"/analysis_*/results_My_Wifi_Test_handshake_*.txt; do
    [[ -f "$logfile" ]] || exit 91
    printf 'SAFE_RESULT_NAME\n'
done
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SAFE_RESULT_NAME", result.stdout)
        self.assertEqual(logs, [])

    def test_different_captures_have_different_identifiers_for_same_essid(self):
        result, _, _ = self.run_view(r'''
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP" 'Mi Wifi' || exit $?
printf 'a second synthetic capture' > "$VIEW_TMP/input.cap"
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP" 'Mi Wifi'
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        for capture in (b"synthetic input, not a handshake", b"a second synthetic capture"):
            capture_id = hashlib.sha256(capture).hexdigest()[:12]
            self.assertIn(f"results_Mi Wifi_handshake_{capture_id}.txt", result.stdout)

    def test_decoder_opens_a_separate_view_with_real_tool_result(self):
        result, logs, capture_exists = self.run_view(r'''
POCKET_TERMINAL_MODE=auto
DISPLAY=:synthetic
TMUX=""
export VIEW_OUTPUT VIEW_STATUS
export -f script
gnome-terminal() {
    printf 'DECODER_WINDOW\n'
    while [[ $1 != -- ]]; do shift; done
    shift
    unset -f run_decoder_view run_live_output position_decoder_window
    "$@"
}
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DECODER_WINDOW", result.stdout)
        self.assertIn("SIMULATED PROGRESS", result.stdout)
        self.assertIn("KEY FOUND! [SIMULATED_MATCH]", result.stdout)
        self.assertIn("Contraseña encontrada", result.stdout)
        self.assertEqual(len(logs), 1)
        self.assertTrue(capture_exists)

    def test_closing_decoder_wrapper_stops_its_progress_viewer(self):
        result, _, _ = self.run_view(r'''
trap() {
    if [[ $1 == decoder_cleanup && $2 == EXIT ]]; then
        printf '%s' "$BASHPID" > "$VIEW_TMP/decoder_pid"
    fi
    builtin trap "$@"
}
script() {
    trap 'printf stopped > "$VIEW_TMP/stopped"; exit 143' TERM
    printf ready > "$VIEW_TMP/ready"
    while :; do :; done
}
run_decoder_view "$VIEW_REPO/lib/live_output.sh" "$VIEW_TMP/log.txt" printf demo &
owner=$!
for ((attempt=0; attempt<100; attempt++)); do
    [[ ! -f "$VIEW_TMP/ready" ]] || break
    sleep 0.01
done
[[ -f "$VIEW_TMP/ready" ]] || { kill -TERM "$owner"; exit 91; }
kill -TERM "$(cat "$VIEW_TMP/decoder_pid")"
wait "$owner"
status=$?
if [[ -f "$VIEW_TMP/stopped" ]]; then printf 'DECODER_CHILD_STOPPED\n'; fi
exit "$status"
''')
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertIn("DECODER_CHILD_STOPPED", result.stdout)

    def test_failure_is_visible_and_status_preserved(self):
        result, logs, capture_exists = self.run_view(r'''
VIEW_OUTPUT='SIMULATED ERROR'
VIEW_STATUS=4
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"
''')
        self.assertEqual(result.returncode, 4)
        self.assertIn("SIMULATED ERROR", result.stdout)
        self.assertIn("código 4", result.stderr)
        self.assertNotIn("[OK]", result.stdout)
        self.assertTrue(capture_exists)

    def test_missing_capture_is_rejected_without_running_tool(self):
        result, logs, _ = self.run_view(r'''
VIEW_OUTPUT='MUST_NOT_RUN'
show_handshake_progress "$VIEW_TMP/missing.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"
''')
        self.assertEqual(result.returncode, 1)
        self.assertIn("captura", result.stderr)
        self.assertNotIn("MUST_NOT_RUN", result.stdout)
        self.assertEqual(logs, [])

    def test_missing_dictionary_is_rejected(self):
        result, logs, _ = self.run_view(
            'show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/missing.txt" "$VIEW_TMP"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("diccionario", result.stderr)
        self.assertEqual(logs, [])

    def test_missing_viewer_is_clear(self):
        result, logs, _ = self.run_view(r'''
unset -f script
command() { return 1; }
run_live_output "$VIEW_TMP/log.txt" printf demo
''')
        self.assertEqual(result.returncode, 127)
        self.assertIn("util-linux", result.stderr)

    def test_no_match_does_not_claim_success(self):
        result, logs, _ = self.run_view(r'''
VIEW_OUTPUT='SIMULATED PROGRESS'
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"
''')
        self.assertEqual(result.returncode, 0)
        self.assertIn("sin una coincidencia", result.stdout)
        self.assertNotIn("[OK]", result.stdout)

    def test_arguments_are_quoted_as_data(self):
        result, logs, _ = self.run_view(r'''
run_live_output "$VIEW_TMP/log.txt" printf '%s' 'text with spaces; $(printf INJECTED)'
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'text with spaces; $(printf INJECTED)')

    def test_cancelled_status_is_reported_without_claiming_success(self):
        result, logs, capture_exists = self.run_view(r'''
VIEW_OUTPUT='SIMULATED PARTIAL OUTPUT'
VIEW_STATUS=130
show_handshake_progress "$VIEW_TMP/input.cap" "$VIEW_TMP/words.txt" "$VIEW_TMP"
''')
        self.assertEqual(result.returncode, 130)
        self.assertIn("interrumpido", result.stderr)
        self.assertNotIn("[OK]", result.stdout)
        self.assertTrue(capture_exists)
        self.assertIn("SIMULATED PARTIAL OUTPUT", logs[0])

    def test_signals_stop_and_reap_the_owned_viewer(self):
        executable = os.environ["POCKET_TEST_BASH"]
        for signal, expected in (("INT", 130), ("TERM", 143), ("HUP", 129)):
            with self.subTest(signal=signal), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                env = dict(os.environ, VIEW_REPO=ROOT.as_posix(), VIEW_TMP=folder.as_posix())
                env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
                body = r'''
set +o posix
source "$VIEW_REPO/lib/live_output.sh" || exit 90
trap() {
    if [[ "$1" == live_output_cleanup && "$2" == EXIT ]]; then
        printf '%s' "$BASHPID" > "$VIEW_TMP/wrapper"
    fi
    builtin trap "$@"
}
script() {
    trap 'printf stopped > "$VIEW_TMP/stopped"; exit 143' TERM
    printf '%s' "$BASHPID" > "$VIEW_TMP/viewer"
    printf ready > "$VIEW_TMP/ready"
    # A harmless simulated viewer with no descendant processes.
    while :; do :; done
}
run_live_output "$VIEW_TMP/log.txt" printf demo
exit $?
'''
                process = subprocess.Popen([executable, "-c", body], env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 5
                    while not (folder / "ready").exists() and time.monotonic() < deadline:
                        if process.poll() is not None:
                            break
                        time.sleep(0.02)
                    self.assertTrue((folder / "ready").exists(), "simulated viewer did not start")
                    target = (folder / "wrapper").read_text()
                    subprocess.run([executable, "-c", 'kill -"$1" "$2"', "--", signal, target],
                                   env=env, check=True, timeout=5, capture_output=True)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, expected, stderr.decode(errors="replace"))
                    self.assertTrue((folder / "stopped").exists(), "viewer was not terminated cleanly")
                    child = (folder / "viewer").read_text()
                    alive = subprocess.run([executable, "-c", 'kill -0 "$1" 2>/dev/null', "--", child],
                                           env=env, timeout=5, capture_output=True)
                    self.assertNotEqual(alive.returncode, 0, "viewer is still running after cancellation")
                finally:
                    if process.poll() is None:
                        # Only terminate PIDs written by this test's own processes.
                        for name in ("wrapper", "viewer"):
                            if (folder / name).exists():
                                subprocess.run([executable, "-c", 'kill -TERM "$1" 2>/dev/null', "--",
                                                (folder / name).read_text()], env=env,
                                               timeout=5, capture_output=True)
                        try:
                            process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate()


if __name__ == "__main__":
    unittest.main()
