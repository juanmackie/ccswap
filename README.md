# ccacc

Switch official Claude Code accounts on macOS, keeping each account's
login, account-bound configuration, history and session files together.

## Requirements

- macOS only. Claude logins are read from and written to the macOS keychain
  with `/usr/bin/security`; the installer and every command except `help` and
  `--version` refuse other platforms.
- Bash (the system Bash 3.2 works), `curl` and `jq`. `openssl` is needed only
  once, to convert encrypted login backups made by older versions.
- Bash or Zsh as the interactive shell for the launch hook.

## Installation

Install or reinstall with:

```bash
curl -fsSL https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh | bash
source "$HOME/.ccacc-shell/hook.sh"
```

The installer deploys `ccacc` and its required `ccacc_shell.sh` companion together
from the latest [GitHub Release](https://github.com/geminiwen/ccacc/releases/latest),
resolved once to a single commit, into `~/.local/bin` by default. If the latest
Release cannot be looked up, it stops and leaves any existing installation unchanged. It configures the hook
without requiring a saved account, passwords or Claude credentials. Source the
printed hook path once to activate it in the current shell, or open a new
interactive terminal. The hook adds the installed directory to PATH. Keep both
files together; moving them or changing shell startup files can require a reinstall.

To choose another absolute **bin directory**:

```bash
curl -fsSL https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh | bash -s -- --prefix /absolute/path/to/bin
```

To install something other than the latest Release, set `CCACC_INSTALL_REF` to a
branch, tag or full commit; it skips the Release lookup. `CCACC_INSTALL_REF=main`
installs the development branch:

```bash
curl -fsSL https://raw.githubusercontent.com/geminiwen/ccacc/main/install.sh | CCACC_INSTALL_REF=main bash
```

Installation rejects symlinked targets or path components. It does not install
packages or require `sudo`. If deployment succeeds but shell setup fails, follow
the printed repair command or rerun the installer after resolving the error.

## Updates

```bash
ccacc update          # Install the latest Release over this ccacc
ccacc update --force  # Reinstall even when already on the latest Release
```

`update` asks GitHub for the latest Release and, when it is newer than the running
version, runs the installer from `main` with `--prefix` set to the directory of the
running `ccacc`. The installer keeps `~/.ccacc/settings.json` and redoes the shell
setup. When already on the latest Release it says so and changes nothing, unless
`--force` is given.

At most once a day, `list`, `current` and `use` look up the latest Release in the
background (they never wait for it) and cache the answer in
`~/.ccacc/update-check.json`. When the cached Release is newer, they print one line
to standard error, e.g. `ccacc 1.2.0 is available (you have 1.1.0); run 'ccacc update'`;
for `use` it comes after the switch, never inside the picker. Other commands never
check. Failures are silent. Set `CCACC_NO_UPDATE_CHECK=1` to turn off both the
lookup and the line.

## Account workflow

```bash
ccacc save personal --timezone Asia/Shanghai # Save the current login and name it
ccacc new                                   # Back up/confirm, choose optional TZ, log out
claude /login                               # Login in the unnamed session
ccacc save work                              # Choose work's saved timezone independently
ccacc use personal                          # Auto-back up outgoing account, choose YOLO, switch
ccacc use                                   # Pick a saved profile in the terminal
ccacc list                                  # List profiles; ls is an alias
ccacc current                               # Show current email, saved name, weekly reset and login expiry
ccacc timezone                              # Read the current session timezone
ccacc timezone work                         # Read a saved profile's timezone
ccacc rename work office                    # Rename a profile; login, history and YOLO choice follow
ccacc rm work                               # Confirm deletion of that profile and stash
ccacc usage daily                           # ccusage over the current and all saved accounts
ccacc help
```

`save <name>` creates a new profile or refreshes the **active** one under its own
name. If `<name>` already exists (its profile JSON, login backup, saved timezone
or history stash) and is not the active profile, save fails before any prompt or
change:

```text
Error: Account 'work' already exists and is not active; choose another name, or run 'ccacc use work' / 'ccacc rm work' first
```

Save and use need no password: login backups are plain files (see below). Save leaves
history and session directories in place while that account is active.
Deleting an active profile leaves its current login/history in place but removes
its saved identity, backup, timezone, policy choices and stored stash.

## Timezones and launches

After the backup step, `new` offers UTC, Asia/Shanghai, Asia/Tokyo,
Australia/Sydney, Europe/London, America/New_York, America/Los_Angeles, or a custom
IANA timezone. Blank or EOF means default: `TZ` is genuinely unset in the Claude
child process. `q` cancels; invalid input fails before process shutdown or account
changes. The command accepts no arguments and never infers a zone from aliases,
account names, host settings or the calling shell's `TZ`.

A selected zone applies immediately to the unnamed session, before login or save.
It does **not** choose the timezone for a later save. Save's priority is:

1. Explicit `ccacc save <name> --timezone <ZONE>`.
2. When re-saving the active profile, its existing timezone.
3. Its own required preset/custom picker, with no blank/default choice.

A successful save or use clears unnamed-session metadata; failed saves retain it.
Repeated `new` with a blank/default choice clears any previous selection. Saved
zones live in `~/.claude/accounts/.timezones/<name>`; an explicit unnamed selection
uses the private validated `.unnamed-session` record. Legacy raw
`.pending-timezone` is never trusted. The read-only `timezone` getter prints one
validated zone with status `0`, or returns empty output and status `3` for an
unnamed default. Invalid active metadata returns status `1` and blocks hooked launch.

On every hooked `claude` launch, the hook reads the current zone and forces
`BROWSER=false`. Only the child environment changes; the caller's `TZ` and
`BROWSER` stay unchanged. The hook calls the native `claude` executable on PATH,
bypassing aliases/functions and copying no old wrappers or fixed flags. It
forwards caller arguments and exit status, without prompting or reading stdin.

Only `use` requires a verified installed hook, including when choosing the active
profile. Save/new do not install, repair or require it, but still require the
companion's path-safety helpers. Without an activated hook, its launch environment
guarantees do not apply. Reinstall when the installed pair or managed hook is stale;
inspect modified/orphaned hook files before following repair instructions.

## Switching and permissions

No-name `use` opens a terminal picker: Up/Down or `j`/`k` moves, Return selects,
and `q`, Esc, Ctrl-C or EOF cancels. It requires terminal stdin and stderr.
Each row shows the profile name, its Claude plan, email and timezone, in colour
unless `NO_COLOR` is set; `list` shows the plan in brackets too. The plan comes
from the saved account metadata only: Claude's own plan name (such as Ultra) when
it is recorded, otherwise the organization type (Team, Enterprise, Pro or Max).

Switching between saved accounts automatically saves the latest outgoing login
and account configuration, then archives its history/session/cache paths,
including `~/.claude/sessions`. After saving and archival succeed, it prints one
summary line on stderr, without printing any contents:

```text
✓ Backed up personal: login, config, 9 history items → ~/.claude/accounts/personal
✓ Switched to work (work@example.com)
```

`-v`/`--verbose` also lists the login backup, configuration snapshot and every
archived path. Named noninteractive switches need no backup confirmation:

```bash
ccacc use work --no-yolo
ccacc use work --yolo
ccacc use work --no-yolo --verbose
```

On a terminal, use asks `YOLO? (y/N)` unless `--yolo` or `--no-yolo` is explicit
(or `alwaysYOLO` is set, see below). No/blank/EOF chooses normal permissions;
Ctrl-C cancels before account changes. Noninteractive use defaults to normal
permissions. The old `--yes` option has been removed and is rejected as an unknown
option. YOLO adds `--dangerously-skip-permissions` to hooked Claude
launches while that profile is active; caller-supplied flags are still forwarded.
The choice belongs to the current selection, not the profile backup. Successful
save/new clear it, and unnamed sessions always use normal permissions.

Choosing the already-active profile changes its launch mode without reloading an
older backup. A clean logged-out unnamed session can use a saved profile directly;
unsaved login or unowned history/session files must be saved first. An otherwise clean unnamed session may retain an empty sessions registry
directory; any entries, including hidden files or links, still require saving.
If the unnamed session is not logged in (for example Claude Code was launched after
`new` and quit at its login screen), `use` lists the files it left behind and asks
once whether to discard them with the same cleanup as `new` and switch; only `y`
continues. Without a terminal it refuses and suggests `ccacc new`, then `ccacc use <name>`.
If Claude Code is running, `save`, switching `use` and `new` first ask
`Claude Code is running. Close it now? (y/N)`. Only `y` closes it and continues;
any other answer cancels with nothing changed. Without a terminal they refuse
instead of asking, and they never close the Claude Code session that runs ccacc.
Switching stops Claude Code processes owned by the current user, including
those using other config directories; it leaves those other directories' credentials
and files unchanged. Fully quit Claude.app and its browser-extension helpers
before cleanup; ccacc warns and refuses cleanup while those owners remain live.

## Settings

ccacc optionally reads `~/.ccacc/settings.json`; the `ccacc` command never
creates or edits it. When the file does not exist, the installer asks once on the
terminal `Always turn on YOLO (skip Claude permission prompts) when switching
accounts? (y/N)` and saves the answer as `alwaysYOLO` (blank means No). It never
asks or writes when the file already exists or no terminal is available, so
reinstalling keeps your choice. The file must contain one JSON object; unknown
keys are ignored.

```json
{
  "alwaysYOLO": true
}
```

| Key | Type | Effect |
| --- | --- | --- |
| `alwaysYOLO` | boolean | When `true`, every `ccacc use` without `--yolo` or `--no-yolo` turns YOLO on without asking, on a terminal or not, and says so on stderr. `--no-yolo` still wins. Missing or `false` keeps the `YOLO? (y/N)` behaviour. |

YOLO means hooked Claude launches skip permission prompts, so enable this only if
you accept that for every account you switch to. `use` reads the file before any
picker, backup migration, process stop or account change. If the file exists but
cannot be read, is not valid JSON, is not an object, or `alwaysYOLO` is not a
boolean, `use` fails with an error naming the file and changes nothing.

## Weekly reset

`save`, `new` and `use` read the live login's weekly limit reset time once, first
thing (for `use`, the outgoing account's), from the same endpoint Claude Code's
`/usage` reads, and record it as `~/.claude/accounts/<name>.weekly`. `list`, the
`use` picker and `current` then show how long until the next reset, rolled
forward a week at a time and rounded down (`4d 7h`, `7h`, `35m`), without going
online again; `current` adds the time itself in this computer's timezone. A profile with no
recorded reset shows none. The lookup uses only an unexpired access token from the
Keychain (never refreshes it) and passes it to `curl` on standard input; when it
fails, an earlier record stays. Set `CCACC_NO_WEEKLY_RESET=1` to turn it off.

## Login expiry

`list` (the LOGIN column) and `current` show when each saved login stops
renewing itself: the time its refresh token expires. After that the profile
needs a fresh `/login`. The time turns yellow with less than 7 days left and
reads `expired` in red once past. The active profile reads the live Keychain
login, which Claude Code may have renewed since the last save; other profiles
read their login backup. Only the timestamp is read; tokens are never shown or
sent anywhere.

`list` prints one line per profile under a header. When that table is wider
than the terminal, each profile takes two lines instead: name, email and plan,
then the weekly reset, login expiry and Surge policies underneath.

## Backup boundaries

| Operation | Saved or moved data |
| --- | --- |
| `save <name>` | Creates a new profile or refreshes the active one; other existing names are refused. Only `claudeAiOauth` goes into `<name>.credentials`; account-bound `~/.claude.json` fields go into `<name>.json`. Save also records the independently chosen timezone and optional Surge policies. Live directories stay in place. |
| `use <name>` | Updates the outgoing login/config backup, moves its account directories into `~/.claude/accounts/<outgoing>/`, and restores the target's saved login/config and directory stash. Saved timezone and Surge choices stay unchanged. |
| `new` | Never creates a named profile. If the current login matches the active profile, it first refreshes that profile's login/config backup (like `use` does for the outgoing account) without asking. If nobody is logged in and no profile is active, it cleans without asking. Otherwise (logged out while a profile is active, a login that does not match the active profile, or a login with no active profile) it asks for confirmation first and never updates any saved profile. It then logs out and resets account state. Archive paths move into the matching active profile's stash; unmatched/unnamed paths are cleared. |

ccacc writes the `Claude Code-credentials` keychain item the same way Claude Code
does: through `/usr/bin/security` with hex data on `security -i`'s standard input,
so the secret never appears in process arguments. The item keeps the access
settings Claude Code expects, so switching does not cause extra "security wants to
use your confidential information" prompts. Only a large item (roughly 1,900 bytes
or more, which no longer fits one `security -i` command line) is passed as an
argument instead, as Claude Code also does, with a warning.

Nothing ccacc saves is encrypted. The login backup `~/.claude/accounts/<name>.credentials`
is plain JSON holding only `claudeAiOauth` (the Claude access and refresh tokens),
written with mode 600 inside the private `accounts` folder. Anyone who can read
your home folder, or a copy of it such as a Time Machine backup, can use that
login. Profile JSON and stashed files, including session JSON and `.key` bytes,
are stored the same way. Session archival preserves those bytes; it does not
restart stopped processes or recreate running sessions.

Older versions encrypted login backups as `<name>.credentials.enc` with a master
password. The first `save` or `use` that finds such files asks for that password
once, converts every backup to a plain file, and only then removes the encrypted
files and `.check.enc`. A converted backup keeps its original fields: one written
before logins became login-only can still carry `mcpOAuth`, which restore writes
back. A wrong or missing password, or any failure, leaves the encrypted backups
untouched and changes nothing else. `rm` deletes either form without a password.

The archive includes these `~/.claude` paths:

```text
backups/  debug/  file-history/  feedback/drafts/  paste-cache/  plans/
projects/  sessions/  session-env/  shell-snapshots/  statsig/  tasks/
telemetry/  todos/  stats-cache.json  history.jsonl  gh-pr-status-cache.json
```

`~/.claude/cache` stays shared and is never archived: its changelog, model catalog
and closed-issue list do not belong to an account and rebuild themselves.

It also includes `~/Library/Caches/claude-cli-nodejs`. `feedback/drafts` is stored
under the stash label `feedback-drafts`; the external CLI cache uses
`cli-nodejs-cache`. `new` additionally clears bounded `daemon`, `jobs`,
remote/policy cache files, plugin directory/catalog caches and recognized
timestamped cleaner recovery copies. Those extra runtime paths are not part of
the account archive.

MCP OAuth stays shared: new login backups hold only `claudeAiOauth`, and unrelated
credential fields are never restored from them. A backup written by an older ccacc
that still carries `mcpOAuth` writes those entries back on restore, replacing live
entries for the same server while keeping live entries the backup does not know
about. Shared device keys, shared MCP configuration, settings, skills,
installed plugins, knowledge, shell hooks and Claude Desktop data remain in place.
Meaningful project MCP definitions/selections survive `new`, including explicit
`false`. Suffixed Keychain items, other Claude config directories and Cowork device
keys are outside the account backup. New keeps the current Surge route; when
Surge is available, save can record policies and use applies saved choices
(also when the account is already active, undoing manual changes in Surge).
`ccacc surge <name>` re-picks an account's policies, with its saved choices
pre-selected, and applies them at once when that account is active. Picking needs
Surge running; `ccacc help` lists the command whenever Surge is installed.

## Usage across accounts

`ccacc usage [ccusage arguments]` runs the installed `ccusage` with
`CLAUDE_CONFIG_DIR` set to `~/.claude` plus every saved profile folder that holds
archived history (`~/.claude/accounts/<name>/projects`), so the current and all
saved accounts are counted. Arguments are passed through unchanged, for example
`ccacc usage daily` or `ccacc usage monthly --json`. It only reads; nothing is
moved or written. Install ccusage first if it is missing.

## Failures and recovery

New checks paths, writability, credentials, stash conflicts and live/unverifiable
runtime owners before cleanup. Symlinks or malformed metadata fail closed.
Cancellation leaves existing account data unchanged. Cleanup stages bounded paths
and snapshots config/session metadata, then restores them where possible if a
later step fails. Save/delete also stage their bounded profile metadata for rollback.

If recovery is incomplete, the error identifies either
`~/.claude/accounts/.cleanup-recovery` or a `.profile-transaction.*` directory.
These guards block further account changes and hooked launches. Inspect its
`manifest.json` and retained config/metadata copies; restore the recorded paths
without overwriting existing data before removing the guard. A failed credential
restore may require a saved profile or a fresh login. Keychain snapshots
stay in memory; cleanup does not create plaintext Keychain recovery files.

A late `use` failure can leave some target state applied. Read the error and inspect
the current account before retrying; the command does not claim a completed switch.
An earlier outgoing-backup report describes the saved backup only; it does not
mean that the target restore or switch completed.

## Releasing

The installer and the update check read GitHub Releases, so a tag alone is not
enough:

1. Bump `VERSION=` near the top of `ccacc` and commit.
2. `git tag -a vX.Y.Z -m "ccacc X.Y.Z"` and `git push origin vX.Y.Z`.
3. `gh release create vX.Y.Z --title "ccacc X.Y.Z" --notes "..."`.

Tags must be `vX.Y.Z`; the installer and update check ignore anything else.

## Development checks

Run from the repository root with temporary/cache paths under `.orca`:

```bash
mkdir -p .orca/uv-cache .orca/tmp .orca/test-home
HOME="$PWD/.orca/test-home" UV_CACHE_DIR="$PWD/.orca/uv-cache" TMPDIR="$PWD/.orca/tmp" uv run --no-project python -m unittest discover -s tests
HOME="$PWD/.orca/test-home" UV_CACHE_DIR="$PWD/.orca/uv-cache" TMPDIR="$PWD/.orca/tmp" uv run --no-project python tests/test_mcp_preservation.py
```

Tests use isolated homes, synthetic credentials/session keys, fake Claude launches
and mocked process/Keychain/Surge/network boundaries. They do not prove a live
Claude login or a production account switch.
