#!/usr/bin/env bash
# Check an installed separate-OS-user daemon (docs/isolation.md) on a real
# host: the boundary between its users, the sudo path for the human, and one
# join approved through it. Run it as root, on a throwaway host only: it
# starts a second daemon and changes a sudoers drop-in while it runs.
#
# The daemon must be running, the agent user listed in isolation.agent_users
# and in the daemon's group. These environment variables say the rest:
#
#   CHECK_DAEMON_USER     the daemon's user (agentconnect, _agentconnect)
#   CHECK_CONFIG          its config.toml
#   CHECK_DATA_DIR        its data directory
#   CHECK_AGENT_DIR       its agent directory
#   CHECK_BIN             the CLI's path, as in the sudoers rule
#   CHECK_RELAY_URL       the relay it uses (a ws:// URL on loopback)
#   CHECK_AGENT           a listed agent user
#   CHECK_STRANGER        a user in the daemon's group, not listed
#   CHECK_PEER            a user that runs the second daemon
#   CHECK_HUMAN           the human: has a sudoers rule, needs a password
#   CHECK_HUMAN_PASSWORD  its password
#
# Prints PASS or FAIL for each check, and exits non-zero after any FAIL.
set -uo pipefail

# As the human, inside a pty: what sudo does about its tickets.
if [[ "${1:-}" == "--sudo-tickets" ]]; then
    as_daemon=(sudo -n -u "$CHECK_DAEMON_USER" "$CHECK_BIN" version)
    as_root=(sudo -n -u root /usr/bin/id -u)
    say() { echo "$1: $2"; }
    outcome() { if "$@" >/dev/null 2>&1; then echo allowed; else echo refused; fi; }
    with_password() { printf '%s\n' "$CHECK_HUMAN_PASSWORD" | sudo -S -p '' "$@" >/dev/null 2>&1; }

    sudo -k
    say no_ticket "$(outcome "${as_daemon[@]}")"
    if with_password -u "$CHECK_DAEMON_USER" "$CHECK_BIN" version; then say with_password allowed; else say with_password refused; fi
    say after_daemon_run "$(outcome "${as_daemon[@]}")"
    sudo -k
    if with_password -u root /usr/bin/id -u; then say root_with_password allowed; else say root_with_password refused; fi
    say root_after_root_run "$(outcome "${as_root[@]}")"
    say daemon_after_root_run "$(outcome "${as_daemon[@]}")"
    sudo -k
    exit 0
fi

: "${CHECK_DAEMON_USER:?}" "${CHECK_CONFIG:?}" "${CHECK_DATA_DIR:?}" "${CHECK_AGENT_DIR:?}" "${CHECK_BIN:?}"
: "${CHECK_RELAY_URL:?}" "${CHECK_AGENT:?}" "${CHECK_STRANGER:?}" "${CHECK_PEER:?}"
: "${CHECK_HUMAN:?}" "${CHECK_HUMAN_PASSWORD:?}"
[[ "$(id -u)" == 0 ]] || { echo "run this as root" >&2; exit 2; }
export CHECK_DAEMON_USER CHECK_BIN CHECK_HUMAN_PASSWORD

failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
# as <user> <command...>, with the user's own groups and home.
as() { local user="$1"; shift; sudo -H -n -u "$user" "$@"; }
as_agent_dir() { local user="$1"; shift; as "$user" env "AC_DATA_DIR=$CHECK_AGENT_DIR" "$CHECK_BIN" "$@"; }
expect_refused() {
    # expect_refused <label> <text the output must hold> <command...>
    local label="$1" text="$2" out code
    shift 2
    out="$("$@" 2>&1)"
    code=$?
    if [[ "$code" != 0 && "$out" == *"$text"* ]]; then
        pass "$label"
    else
        fail "$label (exit $code, expected '$text'): ${out:0:300}"
    fi
}

work="$(mktemp -d)"
chmod 0755 "$work"
peer_pid=""
cleanup() {
    [[ -z "$peer_pid" ]] || kill "$peer_pid" 2>/dev/null
    rm -f /etc/sudoers.d/zz-ac-check
    rm -rf "$work"
}
trap cleanup EXIT

echo "--- the agent user"
if as_agent_dir "$CHECK_AGENT" status --json >"$work/status.json" 2>&1; then
    pass "the agent reaches the daemon from the agent directory"
else
    fail "the agent reaches the daemon: $(head -c 300 "$work/status.json")"
fi
expect_refused "the agent can't read the data directory" "denied" as "$CHECK_AGENT" ls "$CHECK_DATA_DIR"
expect_refused "the agent can't read human-token" "denied" as "$CHECK_AGENT" cat "$CHECK_DATA_DIR/human-token"
if [[ -e "$CHECK_AGENT_DIR/human-token" ]]; then
    fail "the agent directory holds a copy of human-token"
else
    pass "the agent directory holds no human-token"
fi
expect_refused "a human-only command fails as the agent" "human" \
    as_agent_dir "$CHECK_AGENT" approvals approve no-such-request --yes

echo "--- the human token in the wrong hands"
socket="$(find "$CHECK_AGENT_DIR" -maxdepth 1 -type s -name 'agentconnectd*' | head -n 1)"
if [[ -z "$socket" ]]; then
    fail "no API socket in $CHECK_AGENT_DIR"
else
    header="$work/stolen"
    printf 'Authorization: Bearer %s\n' "$(cat "$CHECK_DATA_DIR/human-token")" >"$header"
    chown "$CHECK_AGENT" "$header"
    chmod 0600 "$header"
    answer="$(as "$CHECK_AGENT" curl -s --unix-socket "$socket" -H "@$header" http://localhost/v0/approvals 2>&1)"
    rm -f "$header"
    if [[ "$answer" == *peer_refused* ]]; then
        pass "the human token from the agent's user gets peer_refused"
    else
        fail "the human token from the agent's user: ${answer:0:300}"
    fi
fi

echo "--- a user in the group but not on the list"
expect_refused "the unlisted user is refused" "peer_refused" as_agent_dir "$CHECK_STRANGER" status --json

echo "--- starting the daemon"
expect_refused "the daemon refuses to start as root" "refusing to start" \
    env "AC_CONFIG=$CHECK_CONFIG" "$CHECK_BIN" daemon run
chmod 0644 "$CHECK_DATA_DIR/human-token"
expect_refused "the daemon refuses a readable human-token" "refusing to start" \
    as "$CHECK_DAEMON_USER" env "AC_CONFIG=$CHECK_CONFIG" "$CHECK_BIN" daemon run
chmod 0600 "$CHECK_DATA_DIR/human-token"

echo "--- sudo tickets, per run-as user"
printf '%s ALL=(root) /usr/bin/id\n' "$CHECK_HUMAN" >/etc/sudoers.d/zz-ac-check
chmod 0440 /etc/sudoers.d/zz-ac-check
self="$work/self.sh"
install -m 0755 "$0" "$self"
inner="$self --sudo-tickets"
if [[ "$(uname)" == Darwin ]]; then
    tickets="$(sudo -H -n -u "$CHECK_HUMAN" env "CHECK_DAEMON_USER=$CHECK_DAEMON_USER" "CHECK_BIN=$CHECK_BIN" \
        "CHECK_HUMAN_PASSWORD=$CHECK_HUMAN_PASSWORD" script -q /dev/null "$self" --sudo-tickets 2>&1)"
else
    tickets="$(sudo -H -n -u "$CHECK_HUMAN" env "CHECK_DAEMON_USER=$CHECK_DAEMON_USER" "CHECK_BIN=$CHECK_BIN" \
        "CHECK_HUMAN_PASSWORD=$CHECK_HUMAN_PASSWORD" script -qec "$inner" /dev/null 2>&1)"
fi
# A pty adds carriage returns, and script a NUL at its end of input.
tickets="$(tr -d '\r\000' <<<"$tickets")"
echo "$tickets"
expect_line() {
    # Not anchored at the start: the pty can echo a control character there.
    if grep -q "$1\$" <<<"$tickets"; then pass "$2"; else fail "$2 (no line '$1')"; fi
}
expect_line "no_ticket: refused" "with no ticket, the daemon's user needs the password"
expect_line "with_password: allowed" "the password works for the daemon's user"
expect_line "after_daemon_run: refused" "right after that, it asks again (timestamp_timeout=0)"
expect_line "root_with_password: allowed" "control: the password works for root"
expect_line "root_after_root_run: allowed" "control: root's ticket is reused, so tickets do work here"
expect_line "daemon_after_root_run: refused" "a ticket for root doesn't open the daemon's user"
rm -f /etc/sudoers.d/zz-ac-check

echo "--- one join, approved by the human through sudo"
peer_home="$(as "$CHECK_PEER" sh -c 'cd ~ && pwd')"
as "$CHECK_PEER" mkdir -p "$peer_home/ac"
as "$CHECK_PEER" sh -c "printf '%s\n' '[relay]' 'url = \"$CHECK_RELAY_URL\"' '[daemon]' 'data_dir = \"$peer_home/ac/data\"' 'display_name = \"peer\"' 'keystore = \"file\"' >'$peer_home/ac/config.toml'"
peer_cli() { as "$CHECK_PEER" "$CHECK_BIN" "$@" --config "$peer_home/ac/config.toml"; }
as "$CHECK_PEER" "$CHECK_BIN" daemon run --config "$peer_home/ac/config.toml" >"$work/peer.log" 2>&1 &
peer_pid=$!
for _ in $(seq 1 60); do
    peer_cli status --json >/dev/null 2>&1 && break
    sleep 1
done

# The daemon may still be connecting to the relay.
invite=""
for _ in $(seq 1 30); do
    if invite="$(as_agent_dir "$CHECK_AGENT" invite create --purpose "isolation check" --json 2>"$work/invite.err")"; then
        break
    fi
    invite=""
    sleep 2
done
if [[ -z "$invite" ]]; then
    fail "the agent creates an invite: $(head -c 300 "$work/invite.err")"
else
    pass "the agent creates an invite"
    url="$(jq -r .url <<<"$invite")"
    group="$(jq -r .group_id <<<"$invite")"
    peer_cli accept --yes --wait 120 --json "$url" >"$work/accept.json" 2>&1 &
    accept_pid=$!
    request=""
    for _ in $(seq 1 60); do
        request="$(as "$CHECK_DAEMON_USER" "$CHECK_BIN" approvals list --json --config "$CHECK_CONFIG" 2>/dev/null | jq -r --arg g "$group" '[.approvals[] | select(.group_id == $g)][0].request_id // empty')"
        [[ -z "$request" ]] || break
        sleep 1
    done
    if [[ -z "$request" ]]; then
        fail "the join request reached the daemon"
    else
        pass "the join request reached the daemon"
        if [[ "$(as_agent_dir "$CHECK_AGENT" approvals list --json | jq '.approvals | length')" == 0 ]]; then
            pass "the agent can't see it"
        else
            fail "the agent can see the join request"
        fi
        expect_refused "the agent can't approve it" "human" \
            as_agent_dir "$CHECK_AGENT" approvals approve "$request" --yes
        approve_line="$CHECK_BIN approvals approve $request --yes --config $CHECK_CONFIG"
        pw="$work/pw"
        printf '%s\n' "$CHECK_HUMAN_PASSWORD" >"$pw"
        chown "$CHECK_HUMAN" "$pw"
        chmod 0600 "$pw"
        # shellcheck disable=SC2086  # the line is meant to split into words
        if as "$CHECK_HUMAN" sh -c "sudo -S -p '' -u '$CHECK_DAEMON_USER' $approve_line <'$pw'" >"$work/approve.out" 2>&1; then
            pass "the human approves it with sudo"
        else
            fail "the human approves it with sudo: $(head -c 400 "$work/approve.out")"
        fi
        rm -f "$pw"
    fi
    # Its prompts share the output: the JSON is the last line.
    if wait "$accept_pid" && [[ "$(tail -n 1 "$work/accept.json" | jq -r .status)" == joined ]]; then
        pass "the peer joined"
    else
        fail "the peer joined: $(head -c 400 "$work/accept.json")"
    fi
fi

echo
if [[ "$failures" == 0 ]]; then
    echo "all checks passed"
else
    echo "$failures checks failed"
    exit 1
fi
