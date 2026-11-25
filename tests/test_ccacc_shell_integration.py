"""Core + companion E2E in fixture HOME/startup files; no real account operations."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

# save/use read the weekly reset from Keychain and network; fixtures forbid both.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


ROOT = Path(__file__).resolve().parents[1]
JQ = shutil.which("jq")


# History files that interactive shells write at the HOME root on their own.
SHELL_HISTORY_FILES = {Path(".bash_history"), Path(".zsh_history"), Path(".zhistory"), Path(".sh_history")}


def home_files(home):
    """Files under a fixture HOME for snapshots, without the shells' own history.

    An interactive fixture shell saves its history to a file at the HOME root
    (bash: .bash_history) whenever HISTFILE is not exported to elsewhere. Those
    files are written by the shell, not ccacc, so only these names at the HOME
    root are left out; anything else ccacc writes still shows up.
    """
    return [path for path in home.rglob("*")
            if path.is_file() and path.relative_to(home) not in SHELL_HISTORY_FILES]


class ShellIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.reset_fixture()

    def reset_fixture(self):
        (ROOT / ".orca").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".orca", prefix="shell-integration-")
        self.addCleanup(temporary.cleanup)
        self.fixture = Path(temporary.name).resolve()
        self.home = self.fixture / "home"
        self.accounts = self.home / ".claude/accounts"
        self.accounts.mkdir(parents=True)
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        deployment = self.fixture / "installed tools"
        deployment.mkdir()
        self.core = deployment / "ccacc"
        shutil.copyfile(ROOT / "ccacc", self.core)
        shutil.copyfile(ROOT / "ccacc_shell.sh", deployment / "ccacc_shell.sh")
        # Intentionally non-executable: both configure-shell and the generated
        # runtime timezone query must work through bash.
        self.core.chmod(0o600)
        self.launches = self.fixture / "launches.jsonl"
        self.wrappers = self.fixture / "wrappers.jsonl"
        self.forbidden = self.fixture / "forbidden.log"
        self.argv = self.fixture / "jq-argv"
        self.env = dict(os.environ, HOME=str(self.home), TMPDIR=str(self.fixture),
                        SHELL="/bin/bash", PATH=str(self.bin) + ":" + os.environ["PATH"],
                        LAUNCHES=str(self.launches), WRAPPERS=str(self.wrappers),
                        FORBIDDEN=str(self.forbidden), JQ_ARGV_LOG=str(self.argv),
                        FIXTURE_CORE=str(self.core))
        # An inherited HISTFILE would let the fixture's interactive shells append
        # to the caller's real history; without it they stay in the fixture HOME.
        for name in ("ZDOTDIR", "BASH_ENV", "ENV", "CLAUDE_CONFIG_DIR", "HISTFILE"):
            self.env.pop(name, None)
        for name in ("ps", "kill", "security", "osascript", "surge-cli", "openssl",
                     "curl", "wget", "open", "op"):
            self.executable(name, '#!/bin/bash\nprintf "%s\\n" "$0" >> "$FORBIDDEN"\nexit 98\n')
        # list shows the active login's expiry from the Keychain: a read-only lookup
        # finds no item there (falling back to the backup); any other use fails closed.
        self.executable("security", '#!/bin/bash\n[ "$1" = find-generic-password ] && exit 44\n'
                        'printf "%s\\n" "$0" >> "$FORBIDDEN"\nexit 98\n')
        self.executable("jq", '#!/bin/bash\nprintf "%s\\0" "$@" >> "$JQ_ARGV_LOG"\nexec '
                        + shlex.quote(JQ) + ' "$@"\n')
        self.executable("claude", r'''#!/bin/bash
command jq -cn --args '{tz:env.TZ, cc_tz:env.CC_TZ, browser:env.BROWSER, config:env.CLAUDE_CONFIG_DIR,
    outer:env.OUTER, inner:env.INNER, args:$ARGS.positional}' -- "$@" >> "$LAUNCHES"
''')
        self.executable("_op_agent", r'''#!/bin/bash
command jq -cn --args '{outer:env.OUTER, browser:env.BROWSER, tz:env.TZ,
    args:$ARGS.positional}' -- "$@" >> "$WRAPPERS"
exec "$@"
''')
        (self.home / ".claude.json").write_text('{"userID":"fixture","mcpServers":{"shared":{}}}')
        self.account("sydney", "Australia/Sydney")
        self.account("tokyo", "Asia/Tokyo")
        (self.accounts / ".active").write_text("sydney\n")

    def executable(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def account(self, name, zone):
        (self.accounts / (name + ".json")).write_text("{}")
        metadata = self.accounts / ".timezones"
        metadata.mkdir(exist_ok=True)
        (metadata / name).write_text(zone + "\n")

    def run_process(self, args, success=True, stdin=""):
        result = subprocess.run(args, env=self.env, input=stdin, text=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode == 0, success, (args, result.stdout, result.stderr))
        self.assertFalse(self.forbidden.exists(),
                         self.forbidden.read_text() if self.forbidden.exists() else "")
        return result

    def cli(self, *args, success=True):
        return self.run_process(["/bin/bash", str(self.core), *args], success=success)

    def harness(self, body, success=True, stdin="yes\n"):
        # Source the actual core file so its BASH_SOURCE points to deployment.
        # Only credential/account movement and process/Surge work are replaced.
        mocks = r'''
source "$FIXTURE_CORE" help >/dev/null
migrate_encrypted_backups() { printf 'password\n' >> "$HOME/operations"; }
save_account() { printf '{}\n' > "$ACCOUNTS_DIR/$1.json"; }
load_account() { printf 'load %s\n' "$1" >> "$HOME/operations"; }
backup_active() { :; }
cleanup_stop_processes() { stop_claude; }
cleanup_runtime_is_safe() { :; }
read_credentials() { printf '{}'; }
stop_claude() { printf 'stop\n' >> "$HOME/operations"; }
# Real process checks are covered by test_ccacc_close_prompt.
confirm_close_claude() { :; }
note_device_keys() { :; }
stash_paths() { :; }
unstash_paths() { :; }
reset_account_state() { :; }
replace_credentials() { printf 'credentials\n' >> "$HOME/operations"; }
setup_surge() { :; }
apply_surge() { :; }
'''
        return self.run_process(["/bin/bash", "-c", mocks + "\n" + body], success=success, stdin=stdin)

    def startup(self, shell, definition=None, zdotdir=False):
        self.env["SHELL"] = "/bin/" + shell
        startup = self.home
        if zdotdir:
            startup = self.home / "zsh settings"
            startup.mkdir()
            # This assignment is deliberately NOT exported by .zshenv.
            (self.home / ".zshenv").write_text("ZDOTDIR=" + shlex.quote(str(startup)) + "\n")
        content = "export PATH=" + shlex.quote(self.env["PATH"]) + "\n"
        content += "printf 'fixture startup chatter\\n'\n"
        if definition is not None:
            content += "builtin alias " + shlex.quote("claude=" + definition) + "\n"
        rc = startup / (".bashrc" if shell == "bash" else ".zshrc")
        rc.write_text(content)
        if shell == "bash":
            login = self.home / ".bash_profile"
            login.write_text('. "$HOME/.bashrc"\n')
        else:
            login = startup / ".zlogin"
            login.write_text(content)
        return startup, (rc, login)

    def interactive(self, shell, code, startup=True):
        args = ["/bin/" + shell]
        if not startup:
            args += ["--noprofile", "--norc"] if shell == "bash" else ["-f"]
        # Feed separate input lines to exercise repeated source and launches
        # in the same shell, as a terminal caller would.
        args += ["-il" if startup else "-i"]
        return self.run_process(args, stdin=code)

    def records(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_real_startup_fixed_hook_dynamic_timezone_and_repeat_install(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                # Give each shell its own complete HOME fixture.
                if shell == "zsh":
                    self.reset_fixture()
                definition = ("OUTER='outer value' _op_agent env INNER='inside value' "
                              "BROWSER=firefox TZ=UTC CLAUDE_CONFIG_DIR='/fixture config' "
                              "claude --dangerously-skip-permissions --model 'model name'")
                _, rcs = self.startup(shell, definition, zdotdir=shell == "zsh")
                result = self.cli("configure-shell")
                self.assertIn("Claude shell hook installed.", result.stdout)
                self.assertIn("In your current shell, run: source", result.stdout)
                self.assertIn("New interactive terminals", result.stdout)
                self.assertFalse(self.launches.exists())
                self.assertFalse(self.wrappers.exists())
                self.assertFalse((self.home / ".ccacc-shell/original-alias.json").exists())
                snapshot = {rc: (rc.read_bytes(), rc.stat().st_mtime_ns) for rc in rcs}
                self.cli("configure-shell", "sydney")
                self.assertEqual({rc: (rc.read_bytes(), rc.stat().st_mtime_ns) for rc in rcs}, snapshot)
                self.interactive(shell, ":")
                self.assertFalse(self.launches.exists())
                # One source, two launches, with an active-account change between.
                hook = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
                self.interactive(shell, f". {hook}\nclaude 'user argument'\n"
                                 "printf 'tokyo\\n' > \"$HOME/.claude/accounts/.active\"\n"
                                 "claude 'next argument'\n", startup=False)
                launches = self.records(self.launches)
                self.assertEqual([entry["tz"] for entry in launches], ["Australia/Sydney", "Asia/Tokyo"])
                self.assertEqual([entry["cc_tz"] for entry in launches], ["Australia/Sydney", "Asia/Tokyo"])
                for index, entry in enumerate(launches):
                    self.assertEqual(entry["browser"], "false")
                    self.assertIsNone(entry["config"])
                    self.assertIsNone(entry["outer"])
                    self.assertIsNone(entry["inner"])
                    self.assertEqual(entry["args"], [("user argument", "next argument")[index]])
                self.assertFalse(self.wrappers.exists())
                self.interactive(shell, "claude 'fresh terminal'\n")
                self.assertEqual(self.records(self.launches)[-1]["tz"], "Asia/Tokyo")
                self.assertEqual(self.records(self.launches)[-1]["cc_tz"], "Asia/Tokyo")

    def test_nonexported_zdotdir_metadata_for_existing_and_missing_alias(self):
        startup, rcs = self.startup("zsh", "TZ=UTC claude", zdotdir=True)
        self.assertNotIn("ZDOTDIR", self.env)
        self.cli("configure-shell")
        for rc in rcs:
            self.assertIn("# >>> ccacc shell hook >>>", rc.read_text())
        self.assertFalse((self.home / ".zshrc").exists())
        self.assertFalse((self.home / ".zlogin").exists())

    def test_zsh_typeset_zdotdir_keeps_top_level_startup_scope(self):
        startup = self.home / "typed zsh directory"
        startup.mkdir()
        (self.home / ".zshenv").write_text("typeset ZDOTDIR=" + shlex.quote(str(startup)) + "\n")
        self.env["SHELL"] = "/bin/zsh"
        self.cli("configure-shell")
        self.harness("require_shell_hook")
        self.assertTrue((startup / ".zshrc").exists())
        self.assertTrue((startup / ".zlogin").exists())
        self.assertFalse((self.home / ".zshrc").exists())

    def test_zsh_conditional_login_rcs_context_uses_authentic_options(self):
        for global_rcs in (True, False):
            with self.subTest(global_rcs=global_rcs):
                self.reset_fixture()
                self.env["SHELL"] = "/bin/zsh"
                directory = self.home / "conditional login directory"
                directory.mkdir()
                (self.home / ".zshenv").write_text("" if global_rcs else "unsetopt GLOBAL_RCS\n")
                condition = "-o GLOBAL_RCS" if global_rcs else "! -o GLOBAL_RCS"
                (self.home / ".zprofile").write_text(
                    f"if [[ -o login && -o interactive && -o RCS && {condition} ]]; then\n"
                    "  ZDOTDIR=" + shlex.quote(str(directory)) + "\nfi\n")
                self.cli("configure-shell")
                self.harness("require_shell_hook")
                self.assertTrue((directory / ".zshrc").exists())
                self.assertTrue((directory / ".zlogin").exists())
                self.assertFalse((self.home / ".zshrc").exists())
                self.assertFalse(self.launches.exists())

    def test_zsh_disabled_rcs_does_not_read_skipped_startup_files(self):
        self.env["SHELL"] = "/bin/zsh"
        (self.home / ".zshenv").write_text("unsetopt RCS\n")
        for name in (".zprofile", ".zshrc", ".zlogin"):
            (self.home / name).write_text('printf unexpected > "$HOME/skipped-rc-executed"\n')
        self.cli("configure-shell")
        self.harness("require_shell_hook")
        self.assertFalse((self.home / "skipped-rc-executed").exists())
        self.assertFalse(self.launches.exists())

    def test_zsh_rejects_changed_managed_source_before_evaluating_it(self):
        for version in (2, 3):
            with self.subTest(version=version):
                self.reset_fixture()
                if version == 2:
                    self.legacy_install(2, "zsh")
                else:
                    self.startup("zsh", zdotdir=True)
                    self.cli("configure-shell")
                rc = self.home / "zsh settings/.zshrc"
                content = rc.read_text()
                source = next(line for line in content.splitlines() if line.startswith(". "))
                rc.write_text(content.replace(source, '. "$(printf executed > "$HOME/source-executed")"'))
                before = self.home_snapshot()
                self.cli("configure-shell", success=False)
                self.assertFalse((self.home / "source-executed").exists())
                self.assertEqual(self.home_snapshot(), before)

    def test_missing_alias_installs_default_without_source_time_launch(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                if shell == "zsh":
                    self.reset_fixture()
                startup, _ = self.startup(shell, zdotdir=shell == "zsh")
                self.cli("configure-shell", "tokyo")
                self.assertFalse((self.home / ".ccacc-shell/original-alias.json").exists())
                self.interactive(shell, ":")
                self.assertFalse(self.launches.exists())
                self.interactive(shell, "claude 'plain argument'\n")
                self.assertEqual(self.records(self.launches)[0]["browser"], "false")
                # Installing for another account never changes the active account.
                self.assertEqual(self.records(self.launches)[0]["tz"], "Australia/Sydney")

    def test_runtime_hook_never_prompts_or_uses_legacy_alias_timezone(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                if shell == "zsh":
                    self.reset_fixture()
                self.startup(shell, "TZ=Asia/Tokyo claude", zdotdir=shell == "zsh")
                self.cli("configure-shell")
                (self.accounts / ".timezones/sydney").unlink()
                aliases = self.accounts / ".aliases"
                aliases.mkdir()
                (aliases / "sydney.json").write_text(json.dumps({"env": {"TZ": "Asia/Tokyo"}}))
                before = {path.relative_to(self.home): path.read_bytes()
                          for path in home_files(self.home)}
                hook = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
                result = self.interactive(shell, f". {hook}\nclaude\nexit 0\n", startup=False)
                self.assertIn("cannot read the active account timezone", result.stderr)
                self.assertNotIn("Choose timezone", result.stderr)
                self.assertFalse(self.launches.exists())
                self.assertEqual(before, {path.relative_to(self.home): path.read_bytes()
                                          for path in home_files(self.home)})

    def test_installed_operations_are_read_only_even_with_readonly_startup(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                if shell == "zsh":
                    self.reset_fixture()
                _, rcs = self.startup(shell, "TZ=UTC claude --model fixture", zdotdir=shell == "zsh")
                self.cli("configure-shell")
                paths = list(rcs) + list((self.home / ".ccacc-shell").iterdir())
                for path in rcs:
                    path.chmod(0o444)
                before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in paths}
                # Already-active use must neither ask for a password nor write hook files.
                self.harness('migrate_encrypted_backups() { return 97; }; use_command sydney')
                for command in ("save sydney --timezone Australia/Sydney", "use sydney", "use tokyo",
                                "new"):
                    result = self.harness("main " + command)
                    self.assertNotIn("hook installed", result.stdout)
                    self.assertEqual({p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
                                      for p in paths}, before)
                self.assertEqual(self.cli("timezone", success=False).returncode, 3)
                self.assertFalse(self.launches.exists())

    def test_missing_library_and_unsupported_shell_fail_before_account_operations(self):
        self.startup("bash", "TZ=UTC claude")
        library = self.core.with_name("ccacc_shell.sh")
        library.rename(library.with_suffix(".saved"))
        self.assertIn("ccacc_shell.sh companion",
                      self.cli("configure-shell", "sydney", success=False).stderr)
        for command in ("save next --timezone UTC", "new next --timezone UTC", "use tokyo"):
            result = self.harness("main " + command, success=False)
            self.assertIn("ccacc_shell.sh companion", result.stderr)
            if command.startswith("use "):
                self.assertIn("curl -fsSL", result.stderr)
            self.assertNotIn("shell hook installed", result.stdout)
            self.assertFalse((self.home / "operations").exists())
        library.with_suffix(".saved").rename(library)
        self.env["SHELL"] = "/bin/fish"
        result = self.harness("main use tokyo", success=False)
        self.assertIn("only Bash and Zsh", result.stderr)
        self.assertFalse((self.home / "operations").exists())
        self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")

    def test_non_macos_platform_is_refused_except_help_and_version(self):
        self.executable("uname", '#!/bin/bash\n[ "$1" = -s ] || exit 86\nprintf "Linux\\n"\n')
        before = self.home_snapshot()
        for command in (("list",), ("current",), ("use", "tokyo", "--no-yolo"), ("save", "fresh"),
                        ("new",), ("rm", "tokyo"), ("rename", "tokyo", "osaka"), ("configure-shell",),
                        ("timezone",)):
            with self.subTest(command=command):
                result = self.cli(*command, success=False)
                self.assertIn("ccacc supports macOS only (uname -s reported 'Linux')", result.stderr)
        for command in (("help",), ("--version",), ()):
            with self.subTest(command=command):
                self.cli(*command)
        self.assertEqual(self.home_snapshot(), before)

    def test_save_refuses_existing_inactive_profile_before_prompts_or_changes(self):
        self.startup("bash", "TZ=UTC claude")
        self.cli("configure-shell")
        traces = {
            "tokyo": None,  # an inactive account with profile JSON and timezone
            "jsononly": lambda: (self.accounts / "jsononly.json").write_text("{}"),
            "loginonly": lambda: (self.accounts / "loginonly.credentials").write_text("x"),
            "zoneonly": lambda: (self.accounts / ".timezones/zoneonly").write_text("UTC\n"),
            "stashonly": lambda: ((self.accounts / "stashonly").mkdir(),
                                  (self.accounts / "stashonly/history.jsonl").write_text("x")),
            "danglingonly": lambda: (self.accounts / "danglingonly.json").symlink_to(
                self.fixture / "missing-target"),
        }
        for create in traces.values():
            if create:
                create()
        before = self.home_snapshot()
        for name in traces:
            for args in ("", " --timezone UTC"):
                with self.subTest(name=name, args=args):
                    result = self.harness(f"main save {name}{args}", success=False, stdin="1\n")
                    self.assertIn(f"Error: Account '{name}' already exists and is not active; "
                                  f"choose another name, or run 'ccacc use {name}' / "
                                  f"'ccacc rm {name}' first", result.stderr)
                    self.assertNotIn("Choose timezone", result.stderr)
                    self.assertEqual(self.home_snapshot(), before)
                    self.assertFalse((self.home / "operations").exists())
        self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")
        # The active profile can still be refreshed under its own name, reusing its zone.
        result = self.harness("main save sydney")
        self.assertNotIn("Choose timezone", result.stderr)
        self.assertIn("password", (self.home / "operations").read_text())
        self.assertEqual(self.cli("timezone").stdout, "Australia/Sydney\n")

    def test_configure_shell_needs_metadata_only_and_preserves_credentials(self):
        self.startup("bash", "TZ=UTC claude")
        (self.home / ".claude.json").unlink()
        credentials = self.home / ".claude/.credentials.json"
        credentials.write_text("fixture credential sentinel, deliberately invalid JSON")
        before = credentials.read_bytes(), credentials.stat().st_mtime_ns
        self.cli("configure-shell")
        self.assertEqual((credentials.read_bytes(), credentials.stat().st_mtime_ns), before)
        self.assertFalse(self.launches.exists())

    def home_snapshot(self):
        return {path.relative_to(self.home): (path.read_bytes(), path.stat().st_mtime_ns,
                                             path.stat().st_mode & 0o777)
                for path in self.home.rglob("*") if path.is_file()}

    def test_fresh_install_without_any_claude_state_and_idempotence(self):
        shutil.rmtree(self.home / ".claude")
        (self.home / ".claude.json").unlink()
        self.assertEqual(list(self.home.iterdir()), [])
        self.env["TZ"] = "Invalid/Not_A_Zone"
        self.cli("help")
        self.cli("--version")
        self.cli("timezone", success=False)
        self.cli("configure-shell")
        self.assertFalse((self.home / ".claude").exists())
        self.assertFalse((self.home / ".claude.json").exists())
        before = self.home_snapshot()
        inodes = {p: p.stat().st_ino for p in self.home.rglob("*") if p.is_file()}
        self.cli("configure-shell")
        self.assertEqual(self.home_snapshot(), before)
        self.assertEqual({p: p.stat().st_ino for p in inodes}, inodes)
        self.harness("require_shell_hook")
        self.assertEqual(self.home_snapshot(), before)
        self.cli("timezone", success=False)
        self.assertFalse(self.launches.exists())

    def test_missing_or_corrupt_install_blocks_only_use_before_mutation(self):
        self.startup("bash", "TZ=UTC claude --model fixture")
        # Inputs deliberately omit TZ: rejection must precede the setup menu.
        commands = ("use_command sydney", "use_command tokyo", "main use sydney",
                    "main use tokyo")
        def blocked():
            before = self.home_snapshot()
            for command in commands:
                result = self.harness(command, success=False)
                self.assertIn("curl -fsSL", result.stderr)
                self.assertNotIn("Choose timezone", result.stderr)
                self.assertEqual(self.home_snapshot(), before)
                self.assertFalse((self.home / "operations").exists())
            for args in (("use", "sydney"), ("use", "tokyo")):
                self.cli(*args, success=False)
                self.assertEqual(self.home_snapshot(), before)
        blocked()
        self.cli("configure-shell")
        private = self.home / ".ccacc-shell"
        corruptions = (
            (private / "hook.sh", None),
            (private / "hook.sh", b"# corrupt\n"),
            (private / "managed.json", None),
            (private / "managed.json", b"{}"),
            (private / "managed.json", b'{"version":2,"originalMissing":true}'),
            (self.home / ".bashrc", b"# missing entry\n"),
            (self.home / ".bash_profile", b"# missing login entry\n"),
        )
        for path, content in corruptions:
            with self.subTest(path=path, content=content):
                saved = path.read_bytes()
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content)
                blocked()
                path.write_bytes(saved)
        record_path = private / "managed.json"
        saved_record = record_path.read_bytes()
        record = json.loads(saved_record)
        for key, value in (("script", "/stale/ccacc"), ("shell", "zsh"),
                           ("startupFiles", [str(self.home / ".profile")])):
            record_path.write_text(json.dumps(dict(record, **{key: value})))
            blocked()
        record_path.write_bytes(saved_record)
        rc = self.home / ".bashrc"
        saved = rc.read_bytes()
        for content in (saved + b"alias claude=false\n", saved + saved,
                        saved.replace(b"hook.sh", b"other.sh")):
            rc.write_bytes(content)
            blocked()
        rc.write_bytes(saved)
        # A higher-priority Bash login file makes the old entry stale.
        (self.home / ".bash_profile").rename(self.home / ".profile")
        (self.home / ".bash_profile").write_text("# shadows .profile\n")
        blocked()

    def test_save_and_new_do_not_require_or_repair_an_installed_hook(self):
        self.startup("bash", "TZ=UTC claude")
        self.harness("main save next --timezone UTC")
        self.assertFalse((self.home / ".ccacc-shell").exists())
        self.harness("main new")
        self.assertFalse((self.home / ".ccacc-shell").exists())
        self.cli("configure-shell")
        hook = self.home / ".ccacc-shell/hook.sh"
        hook.write_text('printf executed > "$HOME/hook-executed"\n')
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
                  for p in (self.home / ".bashrc", self.home / ".bash_profile", *hook.parent.iterdir())}
        self.harness("main save second --timezone UTC")
        self.harness("main new")
        self.env["SHELL"] = "/bin/unsupported-fixture-shell"
        self.harness("main save third --timezone UTC")
        self.harness("main new")
        self.assertEqual({p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in before}, before)
        self.assertFalse((self.home / "hook-executed").exists())

    def test_public_install_redirects_to_curl_without_writing(self):
        before = self.home_snapshot()
        result = self.cli("install", success=False)
        self.assertIn("curl -fsSL https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh | bash", result.stderr)
        self.assertEqual(self.home_snapshot(), before)

    def test_source_adds_deployed_prefix_to_path_once_without_account_operations(self):
        shutil.rmtree(self.home / ".claude")
        (self.home / ".claude.json").unlink()
        self.startup("bash")
        self.core.chmod(0o700)
        self.cli("configure-shell")
        hook = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
        result = self.run_process(["/bin/bash", "--noprofile", "--norc", "-c",
                                   f'. {hook}\n. {hook}\ncommand -v ccacc\nprintf "%s\\n" "$PATH"\n'])
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], str(self.core))
        self.assertEqual(lines[1].split(":").count(str(self.core.parent)), 1)
        self.assertFalse(self.launches.exists())
        self.assertFalse((self.home / ".claude").exists())
        self.assertFalse((self.home / ".claude.json").exists())

    def legacy_install(self, version, shell, missing=False):
        definition = "OUTER=old _op_agent env INNER=old claude --dangerously-skip-permissions --model old"
        self.startup(shell, definition, zdotdir=shell == "zsh")
        self.cli("configure-shell")
        private = self.home / ".ccacc-shell"
        record = json.loads((private / "managed.json").read_text())
        record.update(version=version, originalMissing=missing)
        if version == 1:
            record = {"version": 1, "originalMissing": missing}
        (private / "managed.json").write_text(json.dumps(record) + "\n")
        if not missing:
            backup = private / "original-alias.json"
            backup.write_text(json.dumps({"definition": definition}) + "\n")
            backup.chmod(0o640)
        quote = lambda value: "'" + str(value).replace("'", "'\\''") + "'"
        if version == 1:
            if missing:
                command = ' BROWSER=false TZ="$__ccacc_tz" \'claude\' "$@"'
            else:
                command = (' OUTER=old BROWSER=false TZ="$__ccacc_tz" \'_op_agent\' \'env\' '
                           'INNER=old BROWSER=false TZ="$__ccacc_tz" \'claude\' '
                           '\'--dangerously-skip-permissions\' \'--model\' \'old\' "$@"')
        else:
            if missing:
                command = ' BROWSER=false \'env\' "${__ccacc_tz_env[@]}" BROWSER=false \'claude\' "$@"'
            else:
                command = (' OUTER=old BROWSER=false \'_op_agent\' \'env\' INNER=old BROWSER=false '
                           '\'env\' "${__ccacc_tz_env[@]}" BROWSER=false \'claude\' '
                           '\'--dangerously-skip-permissions\' \'--model\' \'old\' "$@"')
        template = (ROOT / f"tests/fixtures/ccacc_hook_v{version}.sh.in").read_text()
        hook = template.replace("@SCRIPT@", quote(self.core)).replace("@COMMAND@", command)
        hook = hook.replace("@DIRECTORY@", quote(self.core.parent))
        (private / "hook.sh").write_text(hook)
        return private

    def test_v1_v2_upgrades_never_launch_or_retain_old_alias_commands(self):
        for version in (1, 2):
            for shell in ("bash", "zsh"):
                for missing in (False, True):
                    with self.subTest(version=version, shell=shell, missing=missing):
                        self.reset_fixture()
                        private = self.legacy_install(version, shell, missing)
                        backups = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
                                   for p in private.glob("original-alias.json")}
                        before = self.home_snapshot()
                        self.harness("require_shell_hook", success=False)
                        self.assertEqual(self.home_snapshot(), before)
                        # Reinstall at another path also covers v1 script-word
                        # decoding and v2 stored deployment-path upgrades.
                        final = self.fixture / "new tools's"
                        final.mkdir()
                        self.core = final / "ccacc"
                        shutil.copyfile(ROOT / "ccacc", self.core)
                        shutil.copyfile(ROOT / "ccacc_shell.sh", final / "ccacc_shell.sh")
                        self.env["FIXTURE_CORE"] = str(self.core)
                        self.cli("configure-shell")
                        self.harness("require_shell_hook")
                        self.assertEqual(json.loads((private / "managed.json").read_text())["version"], 3)
                        self.assertNotIn("_op_agent", (private / "hook.sh").read_text())
                        self.assertEqual(backups, {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
                                                   for p in backups})
                        self.interactive(shell, "claude /login\n")
                        self.assertEqual(self.records(self.launches)[0]["args"], ["/login"])
                        self.assertFalse(self.wrappers.exists())

    def test_previous_owned_v3_hooks_require_explicit_safe_upgrade(self):
        # Earlier shipped v3 launchers: the YOLO prompt, then the 1.2.6 launch-mode
        # getter without CC_TZ. Both are recognised only by an explicit reinstall.
        for fixture in ("ccacc_hook_v3_launch_prompt.sh.in", "ccacc_hook_v3_launch_mode.sh.in"):
            with self.subTest(fixture=fixture):
                self.reset_fixture()
                self.startup("zsh", zdotdir=True)
                self.cli("configure-shell")
                hook = self.home / ".ccacc-shell/hook.sh"
                current = hook.read_bytes()
                quote = lambda value: "'" + str(value).replace("'", "'\\''") + "'"
                previous = (ROOT / "tests/fixtures" / fixture).read_text()
                previous = previous.replace("@SCRIPT@", quote(self.core)).replace("@DIRECTORY@", quote(self.core.parent))
                self.assertNotEqual(previous.encode(), current)
                hook.write_text(previous)
                before = self.home_snapshot()
                self.harness("require_shell_hook", success=False)
                self.assertEqual(self.home_snapshot(), before)
                self.cli("configure-shell")
                self.assertEqual(hook.read_bytes(), current)
                self.assertFalse(self.launches.exists())
                self.harness("require_shell_hook")

    def test_corrupt_legacy_code_is_refused_before_startup_or_writes(self):
        for version in (1, 2):
            self.reset_fixture()
            private = self.legacy_install(version, "zsh")
            with (private / "hook.sh").open("a") as stream:
                stream.write('printf executed > "$HOME/hook-executed"\n')
            before = self.home_snapshot()
            result = self.cli("configure-shell", success=False)
            self.assertIn("inspect and move aside", result.stderr)
            self.assertEqual(self.home_snapshot(), before)
            self.assertFalse((self.home / "hook-executed").exists())

    def test_v3_ignores_and_preserves_unreadable_legacy_backup_contents(self):
        self.startup("zsh", zdotdir=True)
        self.cli("configure-shell")
        backup = self.home / ".ccacc-shell/original-alias.json"
        backup.write_bytes(b"unparsed legacy data\x00\n")
        backup.chmod(0)
        before = backup.stat().st_mtime_ns, backup.stat().st_mode
        self.harness("require_shell_hook")
        self.cli("configure-shell")
        self.assertEqual((backup.stat().st_mtime_ns, backup.stat().st_mode), before)
        backup.chmod(0o600)
        self.assertEqual(backup.read_bytes(), b"unparsed legacy data\x00\n")

    def test_fresh_setup_preserves_orphaned_legacy_backup_as_data(self):
        self.startup("bash")
        private = self.home / ".ccacc-shell"
        private.mkdir()
        backup = private / "original-alias.json"
        backup.write_bytes(b"legacy backup data\x00\n")
        before = backup.read_bytes(), backup.stat().st_mtime_ns, backup.stat().st_mode
        self.cli("configure-shell")
        self.harness("require_shell_hook")
        self.assertEqual((backup.read_bytes(), backup.stat().st_mtime_ns, backup.stat().st_mode), before)

    def test_unnamed_launch_unsets_inherited_and_runtime_wrapper_timezone(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                if shell == "zsh":
                    self.reset_fixture()
                self.startup(shell, "OUTER=outer TZ=UTC _op_agent env INNER=inner TZ=UTC claude --model fixture",
                             zdotdir=shell == "zsh")
                self.cli("configure-shell")
                self.env["TZ"] = "America/New_York"
                self.env["CC_TZ"] = "America/New_York"
                self.executable("_op_agent", '#!/bin/bash\nexport TZ=Asia/Tokyo\nexec "$@"\n')
                self.harness("main new")
                hook = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
                self.interactive(shell, f". {hook}\nclaude /login\n", startup=False)
                launched = self.records(self.launches)[0]
                self.assertEqual(launched["browser"], "false")
                self.assertIsNone(launched["tz"])
                self.assertIsNone(launched["cc_tz"])
                self.assertEqual(launched["args"], ["/login"])
                self.assertEqual((launched["outer"], launched["inner"]), (None, None))
                self.assertFalse((self.accounts / ".pending-timezone").exists())

    def test_getter_distinguishes_unnamed_from_invalid_active_metadata(self):
        self.startup("bash")
        self.cli("configure-shell")
        active = self.accounts / ".active"
        active.unlink()
        before = self.home_snapshot()
        result = self.cli("timezone", success=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "", ""))
        self.assertEqual(self.home_snapshot(), before)
        for content in ("", "sydney\n\n", "missing\n", "../outside\n"):
            active.write_text(content)
            before = self.home_snapshot()
            result = self.cli("timezone", success=False)
            self.assertEqual((result.returncode, result.stdout), (1, ""))
            self.assertEqual(self.home_snapshot(), before)
        active.write_text("sydney\n")
        for content in ("", "{bad", "[]", "{} {}"):
            (self.accounts / "sydney.json").write_text(content)
            self.assertEqual(self.cli("timezone", success=False).returncode, 1)
        (self.accounts / "sydney.json").write_text("{}")
        self.assertEqual(self.cli("timezone").stdout, "Australia/Sydney\n")

    def test_explicit_install_never_sources_corrupt_or_orphaned_hook(self):
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                if shell == "zsh":
                    self.reset_fixture()
                self.startup(shell, "TZ=UTC claude --model fixture", zdotdir=shell == "zsh")
                self.cli("configure-shell")
                private = self.home / ".ccacc-shell"
                hook = private / "hook.sh"
                record = private / "managed.json"
                saved_record = record.read_bytes()
                hook.write_text('printf executed > "$HOME/hook-executed"\n')
                before = self.home_snapshot()
                result = self.cli("configure-shell", success=False)
                self.assertIn("inspect and move aside", result.stderr)
                self.assertEqual(self.home_snapshot(), before)
                self.assertFalse((self.home / "hook-executed").exists())
                record.unlink()
                before = self.home_snapshot()
                self.cli("configure-shell", success=False)
                self.assertEqual(self.home_snapshot(), before)
                self.assertFalse((self.home / "hook-executed").exists())
                # Explicit fixture-only manual recovery retains the verified
                # original record and regenerates a missing hook safely.
                record.write_bytes(saved_record)
                hook.unlink()
                record.unlink()
                self.cli("configure-shell")
                self.harness("require_shell_hook")
                self.assertFalse((self.home / "hook-executed").exists())

    def test_corrupt_hook_is_not_sourced_by_zsh_installed_check(self):
        self.startup("zsh", "TZ=UTC claude", zdotdir=True)
        self.cli("configure-shell")
        hook = self.home / ".ccacc-shell/hook.sh"
        hook.write_text('printf executed > "$HOME/hook-executed"\n')
        before = self.home_snapshot()
        self.harness("use_command sydney", success=False)
        self.assertEqual(self.home_snapshot(), before)
        self.assertFalse((self.home / "hook-executed").exists())
        self.assertFalse((self.home / "operations").exists())

    def test_check_uses_actual_zsh_startup_paths_and_deployment(self):
        self.startup("zsh", "TZ=UTC claude", zdotdir=True)
        self.cli("configure-shell")
        before = self.home_snapshot()
        self.harness("require_shell_hook")
        self.assertEqual(self.home_snapshot(), before)
        # The later login entry is required even when .zshrc still loads the hook.
        login = self.home / "zsh settings/.zlogin"
        saved_login = login.read_bytes()
        login.write_text("# missing login entry\n")
        self.harness("use_command sydney", success=False)
        self.assertFalse((self.home / "operations").exists())
        login.write_bytes(saved_login)
        changed = self.home / "different zsh directory"
        changed.mkdir()
        (self.home / ".zshenv").write_text("ZDOTDIR=" + shlex.quote(str(changed)) + "\n")
        result = self.harness("use_command sydney", success=False)
        self.assertIn("curl -fsSL", result.stderr)
        self.assertFalse((self.home / "operations").exists())

    def test_install_and_save_never_query_or_copy_aliases(self):
        secret = "fixture-secret-never-an-argv-value"
        self.startup("zsh", f"TOKEN={secret} claude --dangerously-skip-permissions", zdotdir=True)
        self.cli("configure-shell")
        self.harness("probe_alias() { return 99; }; main save captured --timezone UTC")
        self.assertFalse((self.accounts / ".aliases").exists())
        self.assertFalse((self.home / ".ccacc-shell/original-alias.json").exists())
        self.assertNotIn(secret.encode(), self.argv.read_bytes())
        self.assertNotIn(secret, (self.home / ".ccacc-shell/hook.sh").read_text())
        self.assertFalse(self.launches.exists())



if __name__ == "__main__":
    unittest.main()
