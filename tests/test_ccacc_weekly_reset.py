"""Fixture-only checks for the weekly reset recorded on save and shown by list/use/current."""

import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "ccacc").read_text().rsplit('main "$@"', 1)[0]
TOKEN = "sk-ant-oat01-fixture_token"
WEEK = 7 * 86400
# Thu 03 Jan 2030 11:00 UTC, given with a +02:00 offset and fractional seconds.
RESET = 1893668400
USAGE = {"five_hour": {"utilization": 2.0, "resets_at": "2030-01-01T05:30:00Z"},
         "seven_day": {"utilization": 85.0, "resets_at": "2030-01-03T13:00:00.375803+02:00"}}


class WeeklyResetTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".orca").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".orca", prefix="weekly-reset-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Path(self.temp.name)
        self.home = self.fixture / "home"
        self.accounts = self.home / ".claude/accounts"
        self.accounts.mkdir(parents=True)
        (self.home / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "a@example.com"}}))
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        self.calls = self.fixture / "curl.log"
        self.stdin = self.fixture / "curl.stdin"
        self.response = self.fixture / "response.json"
        self.response.write_text(json.dumps(USAGE))
        curl = self.bin / "curl"
        curl.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$CALLS"\ncat > "$STDIN"\n'
                        '[ -s "$RESPONSE" ] || exit 22\ncat "$RESPONSE"\n')
        curl.chmod(0o700)
        self.env = dict(os.environ, HOME=str(self.home), TZ="UTC", CALLS=str(self.calls),
                        STDIN=str(self.stdin), RESPONSE=str(self.response),
                        PATH=str(self.bin) + ":" + os.environ["PATH"])
        self.env.pop("CCACC_NO_WEEKLY_RESET", None)

    def bash(self, body, credentials=None):
        if credentials is None:
            credentials = self.login()
        mocks = "read_credentials() { printf '%s' " + repr(json.dumps(credentials)) + "; }\n"
        # Labels use the computer's timezone; pin it to UTC so expectations hold anywhere.
        mocks += 'in_system_timezone() { TZ=UTC "$@"; }\n'
        result = subprocess.run(["/bin/bash", "-c", SOURCE + mocks + body],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def login(self, expires_in=3600):
        return {"claudeAiOauth": {"accessToken": TOKEN,
                                  "expiresAt": int((time.time() + expires_in) * 1000)}}

    def record(self, name, value):
        (self.accounts / (name + ".weekly")).write_text(value)

    def test_prefetch_reads_weekly_reset_without_putting_token_in_argv(self):
        self.assertEqual(self.bash('prefetch_weekly_reset; record_weekly_reset tokyo'), "")
        self.assertEqual((self.accounts / "tokyo.weekly").read_text(), f"{RESET}\n")
        self.assertEqual((self.accounts / "tokyo.weekly").stat().st_mode & 0o777, 0o600)
        argv = self.calls.read_text()
        self.assertIn("https://api.anthropic.com/api/oauth/usage", argv)
        self.assertNotIn(TOKEN, argv)
        self.assertEqual(self.stdin.read_text(), "Authorization: Bearer " + TOKEN + "\n")

    def test_expired_login_is_not_sent_and_failures_keep_the_earlier_record(self):
        self.record("tokyo", "1000000000\n")
        self.bash('prefetch_weekly_reset; record_weekly_reset tokyo', self.login(expires_in=-60))
        self.assertFalse(self.calls.exists())
        for body in ("", "not json", json.dumps({"seven_day": None})):
            self.response.write_text(body)
            self.bash('prefetch_weekly_reset; record_weekly_reset tokyo')
            self.assertEqual((self.accounts / "tokyo.weekly").read_text(), "1000000000\n")

    def test_label_rolls_a_past_reset_forward_by_whole_weeks(self):
        past = RESET - 300 * WEEK  # Same weekday and time, long ago.
        self.record("tokyo", f"{past}\n")
        label = self.bash('weekly_reset_label tokyo').strip()
        self.assertRegex(label, r"^Thu \d\d \w{3} 11:00$")
        expected = past + -(-(int(time.time()) - past) // WEEK) * WEEK
        self.assertEqual(label, time.strftime("%a %d %b %H:%M", time.gmtime(expected)))
        self.record("tokyo", f"{RESET}\n")
        self.assertEqual(self.bash('weekly_reset_label tokyo'), "Thu 03 Jan 11:00\n")

    def test_time_left_is_rounded_down_to_days_hours_or_minutes(self):
        # A little slack past each boundary keeps the clock's ticking out of it.
        for seconds, expected in ((35 * 60 + 30, "35m"), (3600 + 30, "1h"), (7 * 3600 + 1800, "7h"),
                                  (86400 + 30, "1d"), (4 * 86400 + 7 * 3600 + 1800, "4d 7h")):
            self.record("tokyo", f"{int(time.time()) + seconds}\n")
            self.assertEqual(self.bash('weekly_reset_in tokyo'), expected + "\n")
        # A past reset rolls forward whole weeks, as for the label.
        self.record("tokyo", f"{int(time.time()) - 300 * WEEK + 3 * 3600 + 1800}\n")
        self.assertEqual(self.bash('weekly_reset_in tokyo'), "3h\n")
        for value in ("", "soon\n"):
            self.record("tokyo", value)
            self.assertEqual(self.bash('weekly_reset_in tokyo'), "")

    def test_label_ignores_the_session_timezone(self):
        self.record("tokyo", f"{RESET}\n")
        env = dict(self.env, TZ="Australia/Sydney")
        result = subprocess.run(["/bin/bash", "-c", SOURCE + 'weekly_reset_label tokyo'],
                                env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        system = subprocess.run(["env", "-u", "TZ", "date", "-r", str(RESET), "+%a %d %b %H:%M"],
                                text=True, capture_output=True, check=True).stdout
        self.assertEqual(result.stdout, system)

    def test_missing_or_invalid_record_shows_nothing(self):
        (self.accounts / "tokyo.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "t@example.com"}}))
        (self.accounts / ".active").write_text("tokyo\n")
        for value in (None, "", "soon\n", "\x1b[31m1\n"):
            if value is None:
                (self.accounts / "tokyo.weekly").unlink(missing_ok=True)
            else:
                self.record("tokyo", value)
            self.assertEqual(self.bash('weekly_reset_label tokyo'), "")
            self.assertNotRegex(self.bash('list_accounts'), r"WEEKLY|\w{3} \d\d:\d\d")
            self.assertNotIn("Weekly", self.bash('show_current'))
        self.record("tokyo", f"{RESET}\n")
        self.assertRegex(re.sub(r"\x1b\[[0-9;]*m", "", self.bash('list_accounts')), r"WEEKLY\n.* \d+d( \d+h)?\n")
        self.assertRegex(self.bash('show_current'), r"Weekly:     resets in \d+d( \d+h)? \(Thu 03 Jan 11:00\)\n")
        self.assertFalse(self.calls.exists())


class LoginExpiryTests(unittest.TestCase):
    """list shows when each saved login's refresh token expires."""

    setUp = WeeklyResetTests.setUp
    bash = WeeklyResetTests.bash
    record = WeeklyResetTests.record

    def save(self, name, refresh_expires_at):
        (self.accounts / (name + ".json")).write_text(
            json.dumps({"oauthAccount": {"emailAddress": name + "@example.com"}}))
        oauth = {"accessToken": TOKEN, "refreshToken": "sk-ant-ort01-fixture_refresh"}
        if refresh_expires_at is not None:
            oauth["refreshTokenExpiresAt"] = refresh_expires_at
        (self.accounts / (name + ".credentials")).write_text(json.dumps({"claudeAiOauth": oauth}))

    def plain(self, text):
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def row(self, listing, name):
        return next(line for line in listing.splitlines() if self.plain(line)[2:].startswith(name + " "))

    def test_list_shows_backup_expiry_coloured_by_time_left(self):
        now = time.time()
        self.save("later", RESET * 1000)
        self.save("soon", int((now + 3 * 86400) * 1000))
        self.save("gone", int((now - 60) * 1000))
        self.save("unknown", None)
        listing = self.bash("CCACC_NO_WEEKLY_RESET=1 list_accounts", credentials={})
        self.assertNotIn(TOKEN, listing)
        self.assertRegex(self.plain(listing), r"  NAME +EMAIL +LOGIN\n")
        self.assertRegex(self.plain(listing), r"later@example\.com +03 Jan\n")
        self.assertNotIn(YELLOW, self.row(listing, "later"))
        self.assertNotIn(RED, self.row(listing, "later"))
        soon = time.strftime("%d %b %H:%M", time.gmtime(int(now + 3 * 86400)))
        self.assertIn(YELLOW + soon[:6], self.row(listing, "soon"))
        self.assertIn(RED + "expired", self.row(listing, "gone"))
        self.assertRegex(self.plain(self.row(listing, "unknown")), r"unknown@example\.com\s+-$")

    def test_active_account_prefers_the_live_keychain_login(self):
        self.save("tokyo", int((time.time() - 60) * 1000))
        (self.accounts / ".active").write_text("tokyo\n")
        live = {"claudeAiOauth": {"accessToken": TOKEN, "refreshTokenExpiresAt": RESET * 1000}}
        self.assertRegex(self.plain(self.bash("list_accounts", credentials=live)), r"tokyo@example\.com +03 Jan\n")
        # Without a readable live login the backup still answers.
        self.assertRegex(self.plain(self.bash("list_accounts", credentials={})), r"tokyo@example\.com +expired\n")
        self.assertIn("Login:      until 03 Jan 11:00", self.plain(self.bash("show_current", credentials=live)))
        self.assertIn("Login:      " + RED + "expired", self.bash("show_current", credentials={}))

    def test_no_expiry_anywhere_leaves_the_column_out(self):
        self.save("tokyo", None)
        self.assertNotIn("LOGIN", self.bash("list_accounts", credentials={}))
        (self.accounts / ".active").write_text("tokyo\n")
        self.assertNotIn("Login", self.bash("show_current", credentials={}))

    def test_narrow_terminal_moves_details_to_a_second_line(self):
        self.save("tokyo", RESET * 1000)
        self.save("bare", None)
        (self.accounts / "tokyo.surge").write_text(json.dumps({"Claude": "JP1"}))
        self.record("tokyo", f"{int(time.time()) + 4 * 86400 + 7 * 3600 + 1800}\n")
        terminal = "stdout_is_terminal() { :; }\nterminal_columns() { echo %d; }\n"
        wide = self.plain(self.bash(terminal % 200 + "list_accounts", credentials={}))
        self.assertEqual(wide.splitlines()[1:], [
            "  NAME   EMAIL              WEEKLY  LOGIN   SURGE",
            "  bare   bare@example.com   -       -       -",
            "  tokyo  tokyo@example.com  4d 7h   03 Jan  Claude=JP1"])
        width = len(wide.splitlines()[3])
        self.assertEqual(self.plain(self.bash(terminal % width + "list_accounts", credentials={})), wide)
        narrow = self.plain(self.bash(terminal % (width - 1) + "list_accounts", credentials={}))
        self.assertEqual(narrow.splitlines()[1:], [
            "  bare   bare@example.com",
            "  tokyo  tokyo@example.com",
            "         weekly resets in 4d 7h  ·  login 03 Jan  ·  Claude=JP1"])
        # Output that is not a terminal stays on one line whatever the width.
        self.assertEqual(self.plain(self.bash("terminal_columns() { echo 10; }\nlist_accounts", credentials={})), wide)


YELLOW = "\x1b[1;33m"
RED = "\x1b[0;31m"


if __name__ == "__main__":
    unittest.main()
