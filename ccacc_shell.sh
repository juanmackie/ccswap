#!/bin/bash
# Companion to ccacc. Source from Bash; generated hooks support Bash and Zsh.
# Public API: ccacc_install_shell_hook / ccacc_check_shell_hook
# Arguments: ABSOLUTE_CCACC
# Requires jq. Old alias parsing is isolated to explicit v1/v2 upgrades only.

_ccacc_shell_error() { printf 'ccacc shell hook: %s\n' "$*" >&2; }

_ccacc_shell_quote() {
    local value=$1
    value=${value//\'/\'\\\'\'}
    printf "'%s'" "$value"
}

# Refuse links at every path component, nonregular targets, and path traversal.
_ccacc_shell_path() {
    local path=$1 kind=$2 part current='' rest
    case "$path" in /*) ;; *) return 1 ;; esac
    case "$path/" in *'/../'*|*'/./'*|*'//'*) return 1 ;; esac
    rest=${path#/}
    while [ -n "$rest" ]; do
        part=${rest%%/*}
        current="$current/$part"
        [ ! -L "$current" ] || return 1
        if [ "$rest" = "$part" ]; then
            if [ -e "$current" ]; then
                if [ "$kind" = dir ]; then [ -d "$current" ] || return 1
                else [ -f "$current" ] || return 1; fi
            fi
            break
        fi
        [ ! -e "$current" ] || [ -d "$current" ] || return 1
        rest=${rest#*/}
    done
}

# Upgrade-only v1/v2 recognition: a small, non-executing shell lexer. Decode literal quoting to
# identify assignment names and command boundaries, keeping each original word.
# Expansions, operators, comments and continuations are unsupported: accepting
# those without a complete shell parser could change behavior or run code.
_ccacc_shell_legacy_words() {
    local input=$1 i char next state=plain raw='' value='' started=0
    _ccacc_raw=() _ccacc_value=()
    for ((i=0; i<${#input}; i++)); do
        char=${input:i:1}
        case "$state" in
            single)
                raw=$raw$char
                if [ "$char" = "'" ]; then state=plain; else value=$value$char; fi
                ;;
            double)
                raw=$raw$char
                case "$char" in
                    '"') state=plain ;;
                    '$'|'`') return 1 ;;
                    '\')
                        i=$((i+1)); [ "$i" -lt "${#input}" ] || return 1
                        next=${input:i:1}; [ "$next" != $'\n' ] || return 1
                        raw=$raw$next
                        case "$next" in '$'|'`'|'"'|'\') value=$value$next ;; *) value=$value\\$next ;; esac
                        ;;
                    *) value=$value$char ;;
                esac
                ;;
            plain)
                case "$char" in
                    ' '|$'\t')
                        if [ "$started" = 1 ]; then
                            _ccacc_raw+=("$raw"); _ccacc_value+=("$value")
                            raw='' value='' started=0
                        fi
                        ;;
                    "'") state=single; raw=$raw$char; started=1 ;;
                    '"') state=double; raw=$raw$char; started=1 ;;
                    '\')
                        i=$((i+1)); [ "$i" -lt "${#input}" ] || return 1
                        next=${input:i:1}; [ "$next" != $'\n' ] || return 1
                        raw=$raw$char$next; value=$value$next; started=1
                        ;;
                    '$'|'`'|';'|'&'|'|'|'<'|'>'|'('|')'|'{'|'}'|'#'|'~'|'*'|'?'|'['|']'|$'\n'|$'\r') return 1 ;;
                    *) raw=$raw$char; value=$value$char; started=1 ;;
                esac
                ;;
        esac
    done
    [ "$state" = plain ] || return 1
    if [ "$started" = 1 ]; then _ccacc_raw+=("$raw"); _ccacc_value+=("$value"); fi
    [ "${#_ccacc_raw[@]}" -gt 0 ]
}

# Retain literal leading assignments and the supported env / _op_agent env
# prefix. Only BROWSER and TZ assignments are removed. Unknown wrappers fail
# before any files change, rather than losing wrapper options or arguments.
_ccacc_shell_legacy_command() {
    local definition=$1 i=0 token name base prefix='' assignments='' timezone_assignment=''
    # Only used to recognize the exact previous generated hook during an
    # explicit install. Runtime checks accept the current renderer only.
    if [ "${2:-}" = legacy ]; then timezone_assignment=' TZ="$__ccacc_tz"'; fi
    _ccacc_shell_legacy_words "$definition" || return 1
    while [ "$i" -lt "${#_ccacc_raw[@]}" ]; do
        token=${_ccacc_value[$i]}
        if [[ "$token" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
            name=${token%%=*}
            case "${_ccacc_raw[$i]}" in "$name="*) ;; *) return 1 ;; esac
            case "$name" in BROWSER|TZ) ;; *) assignments="$assignments ${_ccacc_raw[$i]}" ;; esac
            i=$((i+1))
        else break; fi
    done
    [ "$i" -lt "${#_ccacc_raw[@]}" ] || return 1
    token=${_ccacc_value[$i]}; base=${token##*/}
    if [ "$base" = _op_agent ]; then
        prefix=$(_ccacc_shell_quote "$token"); i=$((i+1))
        [ "${_ccacc_value[$i]:-}" = env ] || return 1
        prefix="$prefix 'env'"; i=$((i+1))
    elif [ "$base" = env ]; then
        prefix=$(_ccacc_shell_quote "$token"); i=$((i+1))
    fi
    if [ -n "$prefix" ]; then
        # Keep the first assignment group before the wrapper, and the second
        # after env; their order can matter to credential wrappers.
        _ccacc_command="$assignments BROWSER=false$timezone_assignment $prefix"
        assignments=''
        while [ "$i" -lt "${#_ccacc_raw[@]}" ]; do
            token=${_ccacc_value[$i]}
            if [[ "$token" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
                name=${token%%=*}
                case "${_ccacc_raw[$i]}" in "$name="*) ;; *) return 1 ;; esac
                case "$name" in BROWSER|TZ) ;; *) assignments="$assignments ${_ccacc_raw[$i]}" ;; esac
                i=$((i+1))
            else break; fi
        done
    else _ccacc_command=''; fi
    [ "$i" -lt "${#_ccacc_raw[@]}" ] || return 1
    token=${_ccacc_value[$i]}; base=${token##*/}
    [ "$base" = claude ] || return 1
    _ccacc_command="$_ccacc_command$assignments BROWSER=false$timezone_assignment"
    if [ "${2:-}" != legacy ]; then
        # Run env after the wrapper too: even a wrapper that reintroduces its
        # own TZ cannot leak the old account zone into an unnamed Claude child.
        _ccacc_command="$_ccacc_command 'env' \"\${__ccacc_tz_env[@]}\" BROWSER=false"
    fi
    # Quote decoded arguments to prevent source-time alias expansion, globbing,
    # and assignment interpretation in a different shell.
    while [ "$i" -lt "${#_ccacc_raw[@]}" ]; do
        _ccacc_command="$_ccacc_command $(_ccacc_shell_quote "${_ccacc_value[$i]}")"
        i=$((i+1))
    done
    _ccacc_command="$_ccacc_command \"\$@\""
}

# Read every byte, including trailing newlines; reject NUL instead of silently
# dropping it in a shell variable. rc text outside our block stays byte-for-byte.
_ccacc_shell_read() {
    local path=$1 content
    if [ ! -e "$path" ]; then _ccacc_content=''; return 0; fi
    [ -r "$path" ] || return 1
    # Bash read -d '' stops at a NUL; success therefore means malformed input.
    if IFS= read -r -d '' content < "$path"; then return 1; fi
    _ccacc_content=$content
}

_ccacc_shell_rc() {
    local path=$1 begin=$'\n# >>> ccacc shell hook >>>\n' end=$'# <<< ccacc shell hook <<<\n'
    local before after middle
    _ccacc_shell_read "$path" || return 1
    case "$_ccacc_content" in
        *'# >>> ccacc shell hook >>>'*|*'# <<< ccacc shell hook <<<'*)
            case "$_ccacc_content" in *"$begin"*"$end"*) ;; *) return 1 ;; esac
            before=${_ccacc_content%%"$begin"*}
            middle=${_ccacc_content#*"$begin"}
            after=${middle#*"$end"}
            middle=${middle%%"$end"*}
            case "$before$middle$after" in *'# >>> ccacc shell hook >>>'*|*'# <<< ccacc shell hook <<<'*) return 1 ;; esac
            # Unrecognized code inside our markers requires manual repair.
            [ "$middle" = ". $(_ccacc_shell_quote "$private/hook.sh")"$'\n' ] || return 1
            # A newline added before the original block may now separate a
            # formerly unterminated last line from text appended afterwards.
            if [ -n "$before" ] && [ -n "$after" ]; then
                case "$before" in *$'\n') ;; *)
                    case "$after" in $'\n'*) ;; *) before=$before$'\n' ;; esac
                    ;;
                esac
            fi
            _ccacc_content=$before$after
            ;;
    esac
    _ccacc_content="$_ccacc_content$begin. $(_ccacc_shell_quote "$private/hook.sh")
$end"
}

_ccacc_shell_replace() {
    # Preserve mtimes and inodes when generated bytes have not changed.
    if [ -f "$2" ] && cmp -s "$1" "$2"; then return 0; fi
    mv -f "$1" "$2"
}

_ccacc_shell_legacy_v1_text() {
    quoted_script=$(_ccacc_shell_quote "$script")
    cat <<HOOK
# Managed by ccacc. Account timezone is resolved on every launch.
unalias claude 2>/dev/null || :
function __ccacc_launch { (
    __ccacc_tz=\$(command bash $quoted_script timezone) || {
        printf '%s\\n' 'ccacc: cannot read the active account timezone; configure it before launching Claude' >&2
        return 1
    }
    case "\$__ccacc_tz" in
        ''|/*|*..*|*[!A-Za-z0-9_+/-]*)
            printf '%s\\n' 'ccacc: invalid or missing active account timezone' >&2; return 1 ;;
    esac
    if [ ! -f "/usr/share/zoneinfo/\$__ccacc_tz" ] && [ ! -f "/var/db/timezone/zoneinfo/\$__ccacc_tz" ]; then
        printf '%s\\n' 'ccacc: unknown active account timezone' >&2; return 1
    fi
    $_ccacc_command
) }
alias claude='__ccacc_launch'
HOOK
}

_ccacc_shell_legacy_v2_text() {
    quoted_script=$(_ccacc_shell_quote "$script")
    cat <<HOOK
# Managed by ccacc. Account timezone is resolved on every launch.
__ccacc_bin=$(_ccacc_shell_quote "${script%/*}")
case ":\${PATH-}:" in
    *:"\$__ccacc_bin":*) ;;
    *) export PATH="\$__ccacc_bin\${PATH:+:\$PATH}" ;;
esac
unset __ccacc_bin
unalias claude 2>/dev/null || :
function __ccacc_launch { (
    __ccacc_status=0
    __ccacc_tz=\$(command bash $quoted_script timezone) || __ccacc_status=\$?
    case "\$__ccacc_status" in
        0)
            case "\$__ccacc_tz" in
                ''|/*|*..*|*[!A-Za-z0-9_+/-]*)
                    printf '%s\\n' 'ccacc: invalid or missing active account timezone' >&2; return 1 ;;
            esac
            if [ ! -f "/usr/share/zoneinfo/\$__ccacc_tz" ] && [ ! -f "/var/db/timezone/zoneinfo/\$__ccacc_tz" ]; then
                printf '%s\\n' 'ccacc: unknown active account timezone' >&2; return 1
            fi
            export TZ="\$__ccacc_tz"
            __ccacc_tz_env=("TZ=\$__ccacc_tz")
            ;;
        3)
            [ -z "\$__ccacc_tz" ] || return 1
            unset TZ
            __ccacc_tz_env=(-u TZ)
            ;;
        *)
            printf '%s\\n' 'ccacc: cannot read the active account timezone; save its timezone before launching Claude' >&2
            return 1 ;;
    esac
    $_ccacc_command
) }
alias claude='__ccacc_launch'
HOOK
}

# Query initialized startup context only, never aliases. The caller has already
# verified any managed hook as exact known factory code, so startup may define
# its functions safely. Use real login/interactive startup and its RCS options.
_ccacc_shell_probe_context() {
    local output marker="ccacc-context-$RANDOM-$RANDOM-$RANDOM"
    if [ "${SHELL##*/}" = bash ]; then startup_directory=$HOME; return 0; fi
    output=$("$SHELL" -ilc '
        \builtin printf "\n%s\n" "$1"
        \command jq -cn --arg directory "${ZDOTDIR:-$HOME}" "{startupDirectory:\$directory}"
        \builtin printf "%s\n" "$1"
    ' ccacc "$marker" </dev/null 2>/dev/null) || {
        _ccacc_shell_error 'startup context probe failed; inspect Zsh startup files before reinstalling'; return 1;
    }
    startup_directory=$(printf '%s\n' "$output" | jq -Rser --arg marker "$marker" '
        split("\n" + $marker + "\n")
        | if length == 3 then .[1] | fromjson else error("Missing startup context") end
        | .startupDirectory | select(type == "string" and length > 0)
        | select(contains("\u0000") or contains("\n") or contains("\r") | not)') || {
        _ccacc_shell_error 'malformed Zsh startup directory'; return 1;
    }
}

# Decode one literal script word from the known v1 renderer, without evaluating
# shell text. The entire hook must still match a reconstructed template below.
_ccacc_shell_legacy_script() {
    local line word prior='' count=0 prefix='    __ccacc_tz=$(command bash '
    local suffix_old=' timezone) || {' suffix_new=' timezone) || __ccacc_status=$?'
    if jq -e '.version == 2' "$private/managed.json" >/dev/null; then
        jq -er '.script | select(type == "string" and startswith("/") and
            (contains("\u0000") or contains("\n") or contains("\r") | not))' "$private/managed.json"
        return $?
    fi
    while IFS= read -r line; do
        case "$line" in
            "$prefix"*)
                word=${line#"$prefix"}
                case "$word" in
                    *"$suffix_old") word=${word%"$suffix_old"} ;;
                    *"$suffix_new") word=${word%"$suffix_new"} ;;
                    *) return 1 ;;
                esac
                _ccacc_shell_legacy_words "$word" && [ "${#_ccacc_value[@]}" -eq 1 ] || return 1
                prior=${_ccacc_value[0]}; count=$((count+1))
                ;;
        esac
    done <<< "$_ccacc_content"
    [ "$count" -eq 1 ] || return 1
    printf '%s' "$prior"
}

# Exact comparison only: no hook is ever sourced by the installer/checker.
_ccacc_shell_check_text() {
    local expected current_script=$script prior_script version definition
    [ -f "$private/hook.sh" ] && _ccacc_shell_read "$private/hook.sh" || {
        _ccacc_shell_error 'installed hook is missing or unreadable'; return 1;
    }
    version=$(jq -r '.version' "$private/managed.json") || return 1
    if [ "$check_only" = --installed ] && [ "$version" != 3 ]; then
        _ccacc_shell_error 'legacy hook requires explicit reinstall'; return 1
    fi
    if [ "$version" = 3 ]; then
        prior_script=$(jq -er '.script' "$private/managed.json") || return 1
        _ccacc_shell_path "$prior_script" file || return 1
        script=$prior_script
        expected=$(_ccacc_shell_hook_text; printf '.')
        script=$current_script
        [ "$_ccacc_content." = "$expected" ] && return 0
        if [ "$check_only" != --installed ]; then
            script=$prior_script
            expected=$(_ccacc_shell_legacy_v3_text; printf '.')
            [ "$_ccacc_content." = "$expected" ] || expected=$(_ccacc_shell_legacy_v3_launch_mode_text; printf '.')
            script=$current_script
            [ "$_ccacc_content." = "$expected" ] && return 0
        fi
    else
        # Upgrade-only compatibility. Read the old backup only to reconstruct
        # and recognize exact known generated bytes, never to retain its command.
        if jq -e '.originalMissing' "$private/managed.json" >/dev/null; then
            definition=claude
        else
            _ccacc_shell_path "$private/original-alias.json" file &&
                _ccacc_shell_read "$private/original-alias.json" || return 1
            definition=$(printf '%s' "$_ccacc_content" | jq -serj '
                select(length == 1) | .[0].definition
                | select(type == "string" and length > 0 and (contains("\u0000") | not))'; printf '.')
            definition=${definition%.}
            [ -n "$definition" ] || return 1
            _ccacc_shell_read "$private/hook.sh" || return 1
        fi
        prior_script=$(_ccacc_shell_legacy_script) && _ccacc_shell_path "$prior_script" file || return 1
        script=$prior_script
        if [ "$version" = 1 ]; then
            _ccacc_shell_legacy_command "$definition" legacy || return 1
            expected=$(_ccacc_shell_legacy_v1_text; printf '.')
        else
            _ccacc_shell_legacy_command "$definition" || return 1
            expected=$(_ccacc_shell_legacy_v2_text; printf '.')
        fi
        script=$current_script
        [ "$_ccacc_content." = "$expected" ] && return 0
    fi
    _ccacc_shell_error "unverified hook; inspect and move aside $private/hook.sh and $private/managed.json, then rerun the curl installer"
    return 1
}

# Upgrade-only exact-byte recognition of the earlier owned v3 launcher (YOLO prompt).
# Never sourced or emitted as the installed hook.
_ccacc_shell_legacy_v3_text() {
    local quoted_script
    quoted_script=$(_ccacc_shell_quote "$script")
    cat <<HOOK
# Managed by ccacc. Fixed native Claude launcher; no copied alias commands.
__ccacc_bin=$(_ccacc_shell_quote "${script%/*}")
case ":\${PATH-}:" in
    *:"\$__ccacc_bin":*) ;;
    *) export PATH="\$__ccacc_bin\${PATH:+:\$PATH}" ;;
esac
unset __ccacc_bin
unalias claude 2>/dev/null || :
function claude { (
    trap 'exit 130' INT
    __ccacc_status=0
    __ccacc_tz=\$(command bash $quoted_script timezone) || __ccacc_status=\$?
    case "\$__ccacc_status" in
        0)
            case "\$__ccacc_tz" in
                ''|/*|*..*|*[!A-Za-z0-9_+/-]*)
                    printf '%s\\n' 'ccacc: invalid or missing active account timezone' >&2; return 1 ;;
            esac
            if [ ! -f "/usr/share/zoneinfo/\$__ccacc_tz" ] && [ ! -f "/var/db/timezone/zoneinfo/\$__ccacc_tz" ]; then
                printf '%s\\n' 'ccacc: unknown active account timezone' >&2; return 1
            fi
            __ccacc_tz_env=("TZ=\$__ccacc_tz")
            ;;
        3) [ -z "\$__ccacc_tz" ] || return 1; __ccacc_tz_env=(-u TZ) ;;
        *) printf '%s\\n' 'ccacc: cannot read the active account timezone; save its timezone before launching Claude' >&2; return 1 ;;
    esac
    __ccacc_prompt=yes
    for __ccacc_arg in "\$@"; do
        case "\$__ccacc_arg" in
            --) break ;;
            --dangerously-skip-permissions|--help|-h|--version|-v|/login|-p|--print|--print=*) __ccacc_prompt=no ;;
        esac
    done
    if [ "\$__ccacc_prompt" = yes ] && [ -t 0 ] && [ -t 2 ]; then
        printf 'YOLO? (y/N) ' >&2
        __ccacc_answer=''
        if { IFS= read -r __ccacc_answer < /dev/tty; } 2>/dev/null; then
            case "\$__ccacc_answer" in
                y|Y|[yY][eE][sS]) set -- --dangerously-skip-permissions "\$@" ;;
            esac
        fi
    fi
    command env "\${__ccacc_tz_env[@]}" BROWSER=false claude "\$@"
) }
HOOK
}

# Upgrade-only exact-byte recognition of the ccacc 1.2.6 v3 launcher (launch-mode
# getter, no CC_TZ export). Never sourced or emitted as the installed hook.
_ccacc_shell_legacy_v3_launch_mode_text() {
    local quoted_script
    quoted_script=$(_ccacc_shell_quote "$script")
    cat <<HOOK
# Managed by ccacc. Fixed native Claude launcher; no copied alias commands.
__ccacc_bin=$(_ccacc_shell_quote "${script%/*}")
case ":\${PATH-}:" in
    *:"\$__ccacc_bin":*) ;;
    *) export PATH="\$__ccacc_bin\${PATH:+:\$PATH}" ;;
esac
unset __ccacc_bin
unalias claude 2>/dev/null || :
function claude { (
    __ccacc_status=0
    __ccacc_tz=\$(command bash $quoted_script timezone) || __ccacc_status=\$?
    case "\$__ccacc_status" in
        0)
            case "\$__ccacc_tz" in
                ''|/*|*..*|*[!A-Za-z0-9_+/-]*)
                    printf '%s\\n' 'ccacc: invalid or missing active account timezone' >&2; return 1 ;;
            esac
            if [ ! -f "/usr/share/zoneinfo/\$__ccacc_tz" ] && [ ! -f "/var/db/timezone/zoneinfo/\$__ccacc_tz" ]; then
                printf '%s\\n' 'ccacc: unknown active account timezone' >&2; return 1
            fi
            __ccacc_tz_env=("TZ=\$__ccacc_tz")
            ;;
        3) [ -z "\$__ccacc_tz" ] || return 1; __ccacc_tz_env=(-u TZ) ;;
        *) printf '%s\\n' 'ccacc: cannot read the active account timezone; save its timezone before launching Claude' >&2; return 1 ;;
    esac
    # The internal getter is read-only and fails closed. Caller argv is opaque.
    __ccacc_yolo=\$(command bash $quoted_script launch-mode 2>/dev/null) || __ccacc_yolo=false
    if [ "\$__ccacc_yolo" = true ]; then set -- --dangerously-skip-permissions "\$@"; fi
    command env "\${__ccacc_tz_env[@]}" BROWSER=false claude "\$@"
) }
HOOK
}

_ccacc_shell_hook_text() {
    local quoted_script
    quoted_script=$(_ccacc_shell_quote "$script")
    cat <<HOOK
# Managed by ccacc. Fixed native Claude launcher; no copied alias commands.
__ccacc_bin=$(_ccacc_shell_quote "${script%/*}")
case ":\${PATH-}:" in
    *:"\$__ccacc_bin":*) ;;
    *) export PATH="\$__ccacc_bin\${PATH:+:\$PATH}" ;;
esac
unset __ccacc_bin
unalias claude 2>/dev/null || :
function claude { (
    __ccacc_status=0
    __ccacc_tz=\$(command bash $quoted_script timezone) || __ccacc_status=\$?
    case "\$__ccacc_status" in
        0)
            case "\$__ccacc_tz" in
                ''|/*|*..*|*[!A-Za-z0-9_+/-]*)
                    printf '%s\\n' 'ccacc: invalid or missing active account timezone' >&2; return 1 ;;
            esac
            if [ ! -f "/usr/share/zoneinfo/\$__ccacc_tz" ] && [ ! -f "/var/db/timezone/zoneinfo/\$__ccacc_tz" ]; then
                printf '%s\\n' 'ccacc: unknown active account timezone' >&2; return 1
            fi
            export CC_TZ="\$__ccacc_tz"
            __ccacc_tz_env=("TZ=\$__ccacc_tz")
            ;;
        3) [ -z "\$__ccacc_tz" ] || return 1; unset CC_TZ; __ccacc_tz_env=(-u TZ) ;;
        *) printf '%s\\n' 'ccacc: cannot read the active account timezone; save its timezone before launching Claude' >&2; return 1 ;;
    esac
    # The internal getter is read-only and fails closed. Caller argv is opaque.
    __ccacc_yolo=\$(command bash $quoted_script launch-mode 2>/dev/null) || __ccacc_yolo=false
    if [ "\$__ccacc_yolo" = true ]; then set -- --dangerously-skip-permissions "\$@"; fi
    command env "\${__ccacc_tz_env[@]}" BROWSER=false claude "\$@"
) }
HOOK
}

_ccacc_shell_hook() (
    # Subshell contains umask, temporaries and parser variables, not the user's
    # shell. Never source an rc file or evaluate an alias in this process.
    local script=${1:-} check_only=${2:-} private actual record
    local rc path tmp stage startup_directory index=0 committed=0
    local -a rcs stages _ccacc_raw _ccacc_value
    umask 077
    [ "$#" -le 2 ] && { [ -z "$check_only" ] || [ "$check_only" = --validate-only ] || [ "$check_only" = --installed ]; } || return 1
    case "${SHELL##*/}" in bash|zsh) ;; *) _ccacc_shell_error 'only Bash and Zsh are supported'; return 1 ;; esac
    command -v "$SHELL" >/dev/null 2>&1 || { _ccacc_shell_error 'shell executable is unavailable'; return 1; }
    command -v jq >/dev/null 2>&1 || { _ccacc_shell_error 'jq is required'; return 1; }
    _ccacc_shell_path "$script" file && [ -f "$script" ] || {
        _ccacc_shell_error 'ccacc must be an absolute regular file with no symlink components'; return 1;
    }
    _ccacc_shell_path "${HOME:-}" dir && [ -d "$HOME" ] || {
        _ccacc_shell_error 'HOME must be an absolute directory with no symlink components'; return 1;
    }
    private="$HOME/.ccacc-shell"
    _ccacc_shell_path "$private" dir || { _ccacc_shell_error 'unsafe private hook directory'; return 1; }
    for path in "$private/managed.json" "$private/hook.sh"; do
        _ccacc_shell_path "$path" file || { _ccacc_shell_error 'unsafe private hook target'; return 1; }
    done
    if [ -f "$private/managed.json" ]; then
        jq -se 'length == 1 and (.[0] | type == "object" and (
            (.version == 1 and keys == ["originalMissing", "version"] and (.originalMissing | type == "boolean")) or
            (.version == 2 and keys == ["originalMissing", "script", "shell", "startupFiles", "version"] and (.originalMissing | type == "boolean")) or
            (.version == 3 and keys == ["script", "shell", "startupFiles", "version"])) and
            (if .version == 1 then true else
                (.script | type == "string") and (.shell == "bash" or .shell == "zsh") and
                (.startupFiles | type == "array" and length == 2 and all(.[]; type == "string")) end))' "$private/managed.json" >/dev/null || {
            _ccacc_shell_error 'malformed private hook record; inspect and move it aside before reinstalling'; return 1;
        }
        _ccacc_shell_check_text || {
            _ccacc_shell_error "inspect and move aside $private/hook.sh and $private/managed.json before rerunning the curl installer; keep legacy backup files"
            return 1
        }
    else
        [ "$check_only" != --installed ] || { _ccacc_shell_error 'installation record is missing'; return 1; }
        [ ! -e "$private/hook.sh" ] || {
            _ccacc_shell_error "orphaned hook requires manual review: inspect and move aside $private/hook.sh before reinstalling"; return 1;
        }
    fi
    # Reject modified managed source commands at recorded paths before startup
    # can evaluate them. Missing/stale entries are handled by the normal check
    # or explicit repair after the actual startup directory is known.
    if [ -f "$private/managed.json" ] && jq -e '.version >= 2' "$private/managed.json" >/dev/null; then
        while IFS= read -r rc; do
            _ccacc_shell_path "$rc" file && _ccacc_shell_rc "$rc" || {
                _ccacc_shell_error 'unsafe or malformed recorded startup source entry; inspect it before reinstalling'; return 1;
            }
        done < <(jq -r '.startupFiles[]' "$private/managed.json")
    fi
    _ccacc_shell_probe_context || return 1
    case "${SHELL##*/}" in
        zsh)
            case "$startup_directory" in *$'\n'*|*$'\r'*)
                _ccacc_shell_error 'malformed Zsh startup directory'; return 1 ;;
            esac
            _ccacc_shell_path "$startup_directory" dir && [ -d "$startup_directory" ] || {
                _ccacc_shell_error 'Zsh startup directory is unsafe or missing'; return 1;
            }
            # .zlogin runs after .zshrc in interactive login shells, so both
            # files need the hook at the end to override earlier fixed aliases.
            rcs=("$startup_directory/.zshrc" "$startup_directory/.zlogin")
            ;;
        bash)
            rcs=("$HOME/.bashrc")
            # Bash reads the first existing login file, even if it is empty.
            rc="$HOME/.bash_profile"
            for path in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
                _ccacc_shell_path "$path" file || { _ccacc_shell_error 'unsafe Bash login startup target'; return 1; }
                if [ -e "$path" ]; then rc=$path; break; fi
            done
            rcs+=("$rc")
            ;;
        *) _ccacc_shell_error 'only Bash and Zsh startup files are supported'; return 1 ;;
    esac
    for rc in "${rcs[@]}"; do
        _ccacc_shell_path "$rc" file && [ -d "${rc%/*}" ] || {
            _ccacc_shell_error 'startup file or its parent is unsafe or missing'; return 1;
        }
        if [ "$check_only" != --installed ]; then
            [ -w "${rc%/*}" ] && { [ ! -e "$rc" ] || [ -w "$rc" ]; } || {
                _ccacc_shell_error 'startup file and its parent must be writable'; return 1;
            }
        fi
        _ccacc_shell_rc "$rc" || { _ccacc_shell_error 'malformed startup file or managed block'; return 1; }
    done
    record=$(jq -cn --arg script "$script" --arg shell "${SHELL##*/}" \
        --arg first "${rcs[0]}" --arg second "${rcs[1]}" \
        '{version:3,script:$script,shell:$shell,startupFiles:[$first,$second]}') || return 1
    if [ "$check_only" = --installed ]; then
        printf '%s' "$record" | jq -e --slurpfile saved "$private/managed.json" '. == $saved[0]' >/dev/null || {
            _ccacc_shell_error 'installation record does not match this script or startup paths'; return 1;
        }
        for rc in "${rcs[@]}"; do
            [ -f "$rc" ] && _ccacc_shell_read "$rc" || return 1
            actual=$_ccacc_content
            _ccacc_shell_rc "$rc" || return 1
            [ "$actual" = "$_ccacc_content" ] || {
                _ccacc_shell_error 'required managed source entry is missing, stale or misplaced'; return 1;
            }
        done
        return 0
    fi
    [ "$check_only" != --validate-only ] || return 0
    mkdir -p -m 700 "$private" && chmod 700 "$private" || return 1
    tmp=$(mktemp -d "$private/.install.XXXXXXXX") || return 1
    trap 'rm -rf "$tmp"' EXIT
    _ccacc_shell_hook_text > "$tmp/hook.sh" || return 1
    printf '%s\n' "$record" > "$tmp/managed.json" || return 1
    for rc in "${rcs[@]}"; do
        _ccacc_shell_rc "$rc" || return 1
        stage="$tmp/rc.$index"
        if [ -e "$rc" ]; then cp -p "$rc" "$stage" || return 1; fi
        printf '%s' "$_ccacc_content" > "$stage" || return 1
        stages+=("$stage"); index=$((index+1))
    done
    chmod 600 "$tmp/hook.sh" "$tmp/managed.json" || return 1
    # Stage rollback copies before publishing any file. Legacy backup data is
    # neither rewritten nor removed. A failed publish restores prior code/record.
    for path in "$private/hook.sh" "$private/managed.json"; do
        if [ -f "$path" ]; then cp -p "$path" "$tmp/old.${path##*/}" || return 1; fi
    done
    index=0
    for rc in "${rcs[@]}"; do
        if [ -f "$rc" ]; then cp -p "$rc" "$tmp/old.rc.$index" || return 1; fi
        index=$((index+1))
    done
    trap '
        rollback_failed=0
        if [ "$committed" = 0 ]; then
            for path in "$private/hook.sh" "$private/managed.json"; do
                if [ -f "$tmp/old.${path##*/}" ]; then
                    mv -f "$tmp/old.${path##*/}" "$path" || rollback_failed=1
                else rm -f "$path" || rollback_failed=1; fi
            done
            index=0
            for rc in "${rcs[@]}"; do
                if [ -f "$tmp/old.rc.$index" ]; then
                    mv -f "$tmp/old.rc.$index" "$rc" || rollback_failed=1
                else rm -f "$rc" || rollback_failed=1; fi
                index=$((index+1))
            done
        fi
        if [ "$rollback_failed" = 0 ]; then rm -rf "$tmp"
        else _ccacc_shell_error "rollback incomplete; preserve and inspect restore copies in $tmp before reinstalling"; fi
    ' EXIT
    trap 'exit 1' HUP INT TERM
    _ccacc_shell_replace "$tmp/hook.sh" "$private/hook.sh" && _ccacc_shell_replace "$tmp/managed.json" "$private/managed.json" || return 1
    chmod 600 "$private/hook.sh" "$private/managed.json" || return 1
    index=0
    for rc in "${rcs[@]}"; do
        _ccacc_shell_replace "${stages[$index]}" "$rc" || return 1
        index=$((index+1))
    done
    committed=1
    printf 'Claude shell hook installed.\n'
    printf 'In your current shell, run: source %s\n' "$(_ccacc_shell_quote "$private/hook.sh")"
    printf 'New interactive terminals load it automatically.\n'
)

ccacc_install_shell_hook() { _ccacc_shell_hook "$@"; }
ccacc_check_shell_hook() { _ccacc_shell_hook "$1" --installed; }
# Compatibility for explicit installer preflight callers; never an installed check.
ccacc_preflight_shell_hook() { _ccacc_shell_hook "$1" --validate-only; }
