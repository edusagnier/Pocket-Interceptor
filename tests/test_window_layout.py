"""Window placement only, using a synthetic window manager."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("POCKET_TEST_BASH"), "Set POCKET_TEST_BASH")
class WindowLayoutTests(unittest.TestCase):
    def place(self, slot, tmux="", missing_manager=False, unmaximize_failure=False):
        executable = os.environ["POCKET_TEST_BASH"]
        env = dict(os.environ, LAYOUT_REPO=ROOT.as_posix(), DISPLAY=":synthetic", TMUX=tmux,
                   LAYOUT_SLOT=str(slot), MISSING_MANAGER=str(int(missing_manager)),
                   UNMAXIMIZE_FAILURE=str(int(unmaximize_failure)))
        env["PATH"] = str(Path(executable).parent) + os.pathsep + env.get("PATH", "")
        body = r'''
source "$LAYOUT_REPO/lib/window_layout.sh" || exit 90
command() {
    if [[ $1 == -v && $2 == wmctrl && $MISSING_MANAGER == 1 ]]; then return 1; fi
    builtin command "$@"
}
wmctrl() {
    case $1 in
        -d) printf '0 * DG: 1920x1080 VP: 0,0 WA: 0,24 1920x1056 desktop\n' ;;
        -l) printf '0x000001 0 host unrelated\n0x000002 0 host test-unique-window\n' ;;
        *)
            printf 'ACTION=%s\n' "$*"
            if [[ "$*" == *' -b '* && $UNMAXIMIZE_FAILURE == 1 ]]; then return 1; fi
            ;;
    esac
}
position_process_window "$LAYOUT_SLOT" test-unique-window
'''
        return subprocess.run([executable, "-c", body], env=env, capture_output=True,
                              text=True, encoding="utf-8", timeout=5)

    def test_four_slots_occupy_distinct_quadrants(self):
        for slot, geometry in ((1, "0,0,24,960,528"), (2, "0,960,24,960,528"),
                               (3, "0,0,552,960,528"), (4, "0,960,552,960,528")):
            with self.subTest(slot=slot):
                result = self.place(slot)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"ACTION=-i -r 0x000002 -e {geometry}", result.stdout)
                self.assertNotIn("-i -r 0x000001", result.stdout)

    def test_tmux_does_not_move_host_window(self):
        result = self.place(1, tmux="synthetic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ACTION=", result.stdout)

    def test_missing_manager_is_reported_without_failing_command(self):
        result = self.place(1, missing_manager=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("X11 y wmctrl", result.stderr)
        self.assertNotIn("ACTION=", result.stdout)

    def test_geometry_is_requested_even_if_unmaximize_is_unsupported(self):
        result = self.place(2, unmaximize_failure=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ACTION=-i -r 0x000002 -e 0,960,24,960,528", result.stdout)
