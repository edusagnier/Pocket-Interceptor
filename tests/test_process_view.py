"""Terminal routing tests with synthetic commands; no network tools run."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH")
class ProcessViewTests(unittest.TestCase):
    def view(self, setup, body=None):
        executable = os.environ["POCKET_TEST_BASH"]
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, VIEW_REPO=ROOT.as_posix(), VIEW_TMP=Path(directory).as_posix(),
                       DISPLAY=":synthetic", WAYLAND_DISPLAY="", TMUX="", POCKET_TERMINAL_MODE="auto")
            env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
            script = r'''
source "$VIEW_REPO/lib/process_view.sh" || exit 90
gnome-terminal() {
    printf 'GUI_VIEW\n'
    while [[ $1 != -- ]]; do shift; done
    shift
    "$@"
}
'''
            return subprocess.run([executable, "-c", script + setup + (body or r'''
run_process_view 'test view' "$BASH" -c 'printf "%s\n" "$1"; exit 7' -- 'literal; $(echo INJECTED)'
''')], env=env, capture_output=True, text=True, encoding="utf-8", timeout=15)

    def test_gui_waits_for_actual_result_and_preserves_arguments(self):
        result = self.view("")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("GUI_VIEW", result.stdout)
        self.assertIn('literal; $(echo INJECTED)', result.stdout)

    def test_broken_gui_falls_back_once(self):
        result = self.view('gnome-terminal() { return 1; }\n')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("continuando en esta terminal", result.stderr)
        self.assertEqual(result.stdout.count('literal; $(echo INJECTED)'), 1)

    def test_no_display_uses_main_terminal(self):
        result = self.view('DISPLAY=""\n')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("GUI_VIEW", result.stdout)

    def test_tmux_pane_takes_priority_over_gui(self):
        result = self.view(r'''
TMUX=synthetic
tmux() {
    printf 'TMUX_PANE\n'
    "$BASH" -c "${@: -1}"
}
''')
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("TMUX_PANE", result.stdout)
        self.assertNotIn("GUI_VIEW", result.stdout)

    def test_delayed_launcher_does_not_execute_twice(self):
        result = self.view(r'''
gnome-terminal() {
    sleep 3.2
    while [[ $1 != -- ]]; do shift; done
    shift
    "$@"
}
''', r'''
run_process_view test "$BASH" -c 'printf x >> "$VIEW_TMP/count"; sleep 0.5'
status=$?
printf 'COUNT=%s\n' "$(cat "$VIEW_TMP/count")"
exit "$status"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COUNT=x\n", result.stdout)

    def test_decoder_wrapper_function_works_in_external_view(self):
        result = self.view(r'''
synthetic_wrapper() { printf 'WRAPPER=%s\n' "$1"; return 9; }
''', "run_process_view decoder synthetic_wrapper 'with spaces'\n")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertIn("WRAPPER=with spaces", result.stdout)
