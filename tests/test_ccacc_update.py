"""Fixture-only checks for the daily update check and 'ccacc update' (no network)."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest

# Other modules turn these off; here the update check is under test, so only
# the weekly reset (Keychain and network) stays disabled.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"

ROOT = Path(__file__).resolve().parents[1]
CCACC = ROOT / "ccacc"
SOURCE = CCACC.read_text().rsplit('main "$@"', 1)[0]
LATEST_URL = "https://api.github.com/repos/geminiwen/ccacc/releases/latest"
INSTALLER_URL = "https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh"
HINT = "ccacc 1.8.0 is available (you have 1.2.6); run 'ccacc update'\n"

# Any other URL fails, so a fixture can never reach a real host.
CURL = r'''#!/bin/bash
printf '%s\0' "$@" >> "$CALLS"
output= url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) output=$2; shift 2 ;;
        --proto|--proto-redir) [ "$2" = '=https' ] || exit 87; shift 2 ;;
        -H|--connect-timeout|--max-time) shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
[ -z "${CURL_SLEEP:-}" ] || sleep "$CURL_SLEEP"
case "$url" in
    https://api.github.com/repos/geminiwen/ccacc/releases/latest)
        [ "${RELEASE_FAIL:-}" != yes ] || exit 22
        body=$RELEASE_RESPONSE ;;
    https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh)
        [ "${INSTALLER_FAIL:-}" != yes ] || exit 22
        body=$(cat "$FAKE_INSTALLER") ;;
    *) exit 89 ;;
esac
if [ -n "$output" ]; then printf '%s\n' "$body" > "$output"; else printf '%s\n' "$body"; fi
'''
INSTALLER = r'''#!/bin/bash
printf '%s\0' "$@" > "$INSTALLER_LOG"
printf '%s\n' "${CCACC_INSTALL_REF-unset}" "${CCACC_INSTALL_REPO-unset}" > "$INSTALLER_ENV"
echo "fake installer ran"
exit "${INSTALLER_EXIT:-0}"
'''


class UpdateTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".orca").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".orca", prefix="update-")
        self.addCleanup(temporary.cleanup)
        self.fixture = Path(temporary.name).resolve()
        self.home = self.fixture / "home"
        (self.home / ".claude").mkdir(parents=True)
        (self.home / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "a@example.com"}}))
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        (self.bin / "curl").write_text(CURL)
        (self.bin / "curl").chmod(0o700)
        self.installer = self.fixture / "fake-install.sh"
        self.installer.write_text(INSTALLER)
        # A copy of ccacc in a directory with a space, as update's --prefix target.
        self.install_dir = self.fixture / "install dir"
        self.install_dir.mkdir()
        self.script = self.install_dir / "ccacc"
        shutil.copyfile(CCACC, self.script)
        self.script.chmod(0o700)
        self.calls = self.fixture / "curl.log"
        self.installer_log = self.fixture / "installer.log"
        self.installer_env = self.fixture / "installer.env"
        self.cache = self.home / ".ccacc/update-check.json"
        self.env = dict(os.environ, HOME=str(self.home), TZ="UTC", TMPDIR=str(self.fixture),
                        PATH=str(self.bin) + ":" + os.environ["PATH"], CALLS=str(self.calls),
                        RELEASE_RESPONSE=json.dumps({"tag_name": "v1.8.0"}),
                        FAKE_INSTALLER=str(self.installer), INSTALLER_LOG=str(self.installer_log),
                        INSTALLER_ENV=str(self.installer_env))
        for name in ("CCACC_NO_UPDATE_CHECK", "CCACC_INSTALL_REF", "CCACC_INSTALL_REPO", "CLAUDE_CONFIG_DIR",
                     "RELEASE_FAIL", "INSTALLER_FAIL", "INSTALLER_EXIT", "CURL_SLEEP", "BASH_ENV"):
            self.env.pop(name, None)

    # Helpers

    def run_ccacc(self, *args, cwd=None, script=None):
        return subprocess.run(["/bin/bash", str(script or self.script), *args], env=self.env, cwd=cwd,
                              text=True, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)

    def bash(self, body, *args):
        return subprocess.run(["/bin/bash", "-c", SOURCE + body, "bash", *args], env=self.env, text=True,
                              capture_output=True, timeout=30, stdin=subprocess.DEVNULL)

    def urls(self):
        if not self.calls.exists():
            return []
        return [arg for arg in self.calls.read_bytes().decode().split("\0") if arg.startswith("https://")]

    def write_cache(self, latest, age=0, raw=None):
        self.cache.parent.mkdir(mode=0o700, exist_ok=True)
        body = raw if raw is not None else json.dumps({"checked_at": int(time.time()) - age, "latest": latest})
        self.cache.write_text(body)

    def read_cache(self):
        return json.loads(self.cache.read_text())

    def wait_for(self, condition, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if condition():
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        self.fail("background update check did not finish")

    def wait_for_cache(self, latest):
        self.wait_for(lambda: self.read_cache().get("latest") == latest)

    def assert_no_refresh(self):
        # Negative check for a detached process: give it time to show up.
        time.sleep(1)
        self.assertEqual(self.urls(), [])

    # Version comparison

    def test_version_compare_is_numeric_per_component(self):
        cases = [("1.10.0", "1.9.9", True), ("1.1.0", "1.1.0", False), ("1.0.9", "1.1.0", False),
                 ("2.0.0", "10.0.0", False), ("10.0.0", "9.99.99", True), ("1.2.60", "1.2.9", True),
                 ("01.2.3", "1.2.2", True), ("1.02.0", "1.2.0", False),
                 ("99999999999999999999.0.0", "99999999999999999998.0.0", True),
                 ("1.2", "1.1.0", False), ("v1.2.0", "1.1.0", False), ("1.2.0-rc1", "1.1.0", False),
                 ("", "1.1.0", False), ("1.2.0\n", "1.1.0", False)]
        for newer, older, expected in cases:
            with self.subTest(newer=newer, older=older):
                result = self.bash('version_newer "$1" "$2"', newer, older)
                self.assertEqual(result.returncode == 0, expected, result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")

    # Hint from the cache

    def test_hint_printed_once_to_stderr_for_newer_release(self):
        self.write_cache("1.8.0")
        result = self.bash("show_update_hint")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", HINT))

    def test_no_hint_for_equal_older_or_invalid_cache(self):
        now = int(time.time())
        raws = [json.dumps({"checked_at": now, "latest": value})
                for value in ("1.1.0", "1.0.9", "0.9.0", "1.2", "v1.2.0", "1.2.0-beta", "1.2.0\n",
                              "1.2.0\u001b[31m", "\u001b]0;pwned\u0007", "9.9.9 ", 120, None)]
        raws += ["", "not json", "[]", "null", json.dumps({"latest": "1.2.0"}),
                 json.dumps({"checked_at": "now", "latest": "1.2.0"}),
                 json.dumps({"checked_at": now, "latest": "1.2.0"}) * 2]
        for raw in raws:
            with self.subTest(raw=raw):
                self.write_cache(None, raw=raw)
                result = self.bash("show_update_hint")
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_linked_cache_is_ignored(self):
        target = self.fixture / "elsewhere.json"
        target.write_text(json.dumps({"checked_at": int(time.time()), "latest": "1.8.0"}))
        self.cache.parent.mkdir(mode=0o700)
        self.cache.symlink_to(target)
        self.assertEqual(self.bash("show_update_hint").stderr, "")
        # The refresh cannot record its attempt, so it neither replaces the link,
        # writes through it, nor goes to the network on every run.
        self.env["RELEASE_RESPONSE"] = json.dumps({"tag_name": "v3.0.0"})
        self.assertEqual(self.run_ccacc("list").stderr, "")
        self.assert_no_refresh()
        self.assertTrue(self.cache.is_symlink())
        self.assertEqual(json.loads(target.read_text())["latest"], "1.8.0")

    # list/current/use: background refresh and hint

    def test_list_refreshes_in_background_and_writes_private_cache(self):
        result = self.run_ccacc("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")  # nothing cached yet
        self.wait_for_cache("1.8.0")
        self.assertEqual(self.urls(), [LATEST_URL])
        argv = self.calls.read_bytes().decode().split("\0")
        for flag in ("--disable", "--fail", "--proto", "--proto-redir"):
            self.assertIn(flag, argv)
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.cache.parent.stat().st_mode), 0o700)
        self.assertLessEqual(abs(self.read_cache()["checked_at"] - time.time()), 60)
        self.assertEqual(list(self.cache.parent.glob(".update-check.*")), [])
        # The next run prints the hint from the cache and does not refresh again.
        second = self.run_ccacc("list")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stderr, HINT)
        self.assertNotIn("is available", second.stdout)
        time.sleep(1)
        self.assertEqual(self.urls(), [LATEST_URL])

    def test_command_never_waits_on_the_network(self):
        self.env["CURL_SLEEP"] = "4"
        started = time.time()
        result = self.run_ccacc("list")
        self.assertLess(time.time() - started, 3, "list waited for the update check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.wait_for_cache("1.8.0")

    def test_refresh_skipped_when_cache_is_fresh(self):
        self.write_cache("1.2.6", age=23 * 3600)
        result = self.run_ccacc("current")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assert_no_refresh()
        self.assertEqual(self.read_cache()["latest"], "1.2.6")

    def test_stale_or_future_cache_is_refreshed_and_hint_uses_cached_value(self):
        for age in (25 * 3600, -3 * 86400):
            with self.subTest(age=age):
                self.calls.unlink(missing_ok=True)
                self.write_cache("1.8.0", age=age)
                self.env["RELEASE_RESPONSE"] = json.dumps({"tag_name": "v1.9.0"})
                result = self.run_ccacc("current")
                self.assertEqual(result.returncode, 0, result.stderr)
                # The hint reads only the cache as it stood; it never waits for the refresh.
                self.assertEqual(result.stderr, HINT)
                self.wait_for_cache("1.9.0")
                self.assertEqual(self.urls(), [LATEST_URL])

    def test_network_failure_is_silent_and_retried_only_after_a_day(self):
        self.write_cache("1.8.0", age=2 * 86400)
        self.env["RELEASE_FAIL"] = "yes"
        result = self.run_ccacc("list")
        self.assertEqual(result.stderr, HINT)
        self.wait_for(lambda: self.urls() and time.time() - self.read_cache()["checked_at"] < 60)
        time.sleep(0.5)
        self.assertEqual(self.read_cache()["latest"], "1.8.0")  # last known version kept
        self.calls.unlink()
        self.assertEqual(self.run_ccacc("list").stderr, HINT)
        self.assert_no_refresh()

    def test_garbage_release_response_is_not_cached(self):
        for response in ('{"tag_name":"v1.8.0\\u001b[31m"}', '{"tag_name":"1.8.0"}', "not json", "[]"):
            with self.subTest(response=response):
                self.calls.unlink(missing_ok=True)
                self.cache.unlink(missing_ok=True)
                self.env["RELEASE_RESPONSE"] = response
                self.run_ccacc("list")
                self.wait_for(lambda: self.urls() and self.cache.exists())
                time.sleep(0.5)
                self.assertIsNone(self.read_cache()["latest"])
                self.assertEqual(self.run_ccacc("list").stderr, "")

    def test_opt_out_disables_refresh_and_hint(self):
        self.env["CCACC_NO_UPDATE_CHECK"] = "1"
        self.write_cache("1.8.0", age=2 * 86400)
        before = self.cache.read_text()
        for command in ("list", "ls", "current"):
            with self.subTest(command=command):
                result = self.run_ccacc(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
        self.assertEqual(self.bash("show_update_hint").stderr, "")
        self.assert_no_refresh()
        self.assertEqual(self.cache.read_text(), before)

    def test_opt_out_never_creates_the_cache(self):
        self.env["CCACC_NO_UPDATE_CHECK"] = "1"
        self.run_ccacc("list")
        self.assert_no_refresh()
        self.assertFalse((self.home / ".ccacc").exists())

    def test_other_commands_neither_refresh_nor_hint(self):
        self.write_cache("1.8.0", age=2 * 86400)
        for args in (("timezone",), ("launch-mode",), ("help",), ("-v",), ("--version",), ()):
            with self.subTest(args=args):
                result = self.run_ccacc(*args)
                self.assertNotIn("is available", result.stdout + result.stderr)
        self.assert_no_refresh()

    def test_use_hint_follows_success_only(self):
        self.write_cache("1.8.0")
        # The picker and switch write to stderr; the hint must come after them.
        result = self.bash('use_command() { echo "picker and switch" >&2; }\nmain use')
        self.assertEqual((result.returncode, result.stderr), (0, "picker and switch\n" + HINT))
        failed = self.bash('use_command() { echo "cancelled" >&2; return 130; }\nmain use')
        self.assertEqual((failed.returncode, failed.stderr), (130, "cancelled\n"))
        self.assert_no_refresh()

    def test_failure_status_survives_a_condition(self):
        # Inside a condition set -e is off; the hint must not turn a failure into success.
        self.write_cache("1.8.0")
        for command, mock in (("use", "use_command"), ("list", "list_accounts"), ("current", "show_current")):
            with self.subTest(command=command):
                result = self.bash(mock + '() { return 7; }\n'
                                   'if main ' + command + '; then echo succeeded; else echo "status $?"; fi')
                self.assertEqual((result.stdout, result.stderr), ("status 7\n", ""))

    def test_use_starts_the_refresh_before_the_command(self):
        self.write_cache("1.2.6", age=2 * 86400)
        result = self.bash('use_command() { return 1; }\nmain use')
        self.assertEqual((result.returncode, result.stderr), (1, ""))
        self.wait_for_cache("1.8.0")

    # ccacc update

    def installer_args(self):
        return self.installer_log.read_bytes().decode().rstrip("\0").split("\0")

    def test_update_installs_latest_release_into_running_directory(self):
        self.env.update(CCACC_INSTALL_REF="evil-branch", CCACC_INSTALL_REPO="evil/repo")
        result = self.run_ccacc("update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.installer_args(), ["--prefix", str(self.install_dir)])
        # A source override in the environment would install something else.
        self.assertEqual(self.installer_env.read_text(), "unset\nunset\n")
        self.assertEqual(self.urls(), [LATEST_URL, INSTALLER_URL])
        self.assertIn("Updating ccacc 1.2.6 to 1.8.0 in " + str(self.install_dir), result.stdout)
        self.assertIn("fake installer ran", result.stdout)
        self.assertEqual(self.read_cache()["latest"], "1.8.0")
        self.assertEqual(list(self.fixture.glob("ccacc-update.*")), [])

    def test_update_through_relative_path_passes_absolute_prefix(self):
        result = self.run_ccacc("update", cwd=self.install_dir, script="ccacc")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.installer_args(), ["--prefix", str(self.install_dir)])

    def test_update_refuses_same_or_older_version_without_force(self):
        for tag, message in (("v1.2.6", "already the latest release"), ("v1.0.0", "newer than the latest release")):
            with self.subTest(tag=tag):
                self.calls.unlink(missing_ok=True)
                self.env["RELEASE_RESPONSE"] = json.dumps({"tag_name": tag})
                result = self.run_ccacc("update")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(message, result.stdout)
                self.assertIn("--force", result.stdout)
                self.assertEqual(self.urls(), [LATEST_URL])
                self.assertFalse(self.installer_log.exists())

    def test_update_force_reinstalls_same_version(self):
        self.env["RELEASE_RESPONSE"] = json.dumps({"tag_name": "v1.2.6"})
        result = self.run_ccacc("update", "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.installer_args(), ["--prefix", str(self.install_dir)])

    def test_update_fails_closed(self):
        cases = [({"RELEASE_FAIL": "yes"}, "Cannot read the latest ccacc release"),
                 ({"RELEASE_RESPONSE": '{"tag_name":"main"}'}, "Cannot read the latest ccacc release"),
                 ({"INSTALLER_FAIL": "yes"}, "Cannot download the ccacc installer"),
                 ({"INSTALLER_EXIT": "1"}, "installer failed")]
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                self.env = {key: value for key, value in self.env.items()
                            if key not in ("RELEASE_FAIL", "INSTALLER_FAIL", "INSTALLER_EXIT")}
                self.env["RELEASE_RESPONSE"] = json.dumps({"tag_name": "v1.8.0"})
                self.env.update(overrides)
                result = self.run_ccacc("update")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        self.assertEqual(self.run_ccacc("update", "--bogus").returncode, 1)

    def test_help_lists_update(self):
        self.assertIn("update", self.run_ccacc("help").stdout)
        self.assertEqual(self.run_ccacc("-v").stdout, "ccacc v1.2.6\n")


if __name__ == "__main__":
    unittest.main()
