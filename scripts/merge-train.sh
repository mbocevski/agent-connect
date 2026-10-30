#!/usr/bin/env bash
# Merge an ordered list of PRs unattended, with the same gates as by hand.
#
# For each PR in turn: `just update-branch` if it is behind its base, wait for
# its checks, then `just merge`. The train stops at the first PR that has a
# rebase conflict, fails a check, times out or is refused, and leaves that PR
# and the ones after it alone. Every merge goes through `just merge` and every
# rebase through `just update-branch`, so nothing here can skip their gates.
#
# The rebase runs in the worktree that has the PR's branch, or in a temporary
# one under target/ when none does, since update-branch signs locally. A rebase
# that stops on a conflict is aborted, so the branch stays as it was.
#
# usage: scripts/merge-train.sh <pr-number> [<pr-number>...]
set -euo pipefail

# Hooks and wrappers export these; they would point git at the wrong repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

usage() { echo "usage: just merge-train <pr-number> [<pr-number>...]" >&2; exit 2; }
[[ $# -gt 0 ]] || usage
seen=" "
for pr in "$@"; do
    [[ "$pr" =~ ^[1-9][0-9]*$ ]] || usage
    [[ "$seen" != *" $pr "* ]] || { echo "merge-train: #$pr is listed twice" >&2; exit 2; }
    seen+="$pr "
done

timeout_secs="${AC_TRAIN_TIMEOUT_SECS:-5400}"
poll_secs="${AC_TRAIN_POLL_SECS:-30}"
remote="${AC_REMOTE:-origin}"
# How many times one PR may be rebased because main moved during its wait.
max_rounds=3

root="$(git rev-parse --show-toplevel)"
cd "$root"
log="$(mktemp)"
temp_worktree=""
temp_branch=""

remove_temp_worktree() {
    if [[ -n "$temp_worktree" ]]; then
        git worktree remove --force "$temp_worktree" >/dev/null 2>&1 || true
        temp_worktree=""
    fi
    if [[ -n "$temp_branch" ]]; then
        git branch -q -D "$temp_branch" >/dev/null 2>&1 || true
        temp_branch=""
    fi
}
cleanup() { remove_temp_worktree; rm -f "$log"; }
trap cleanup EXIT

later=""
stop() {
    echo "merge-train: stopped at #$pr: $*" >&2
    [[ -z "$later" ]] || echo "merge-train: not started:$later" >&2
    exit 1
}
step() { echo "#$pr ${head:0:12} $1: $2"; }
show_log() { tail -n 20 "$log" >&2; }

# Sets state, draft, base, branch, head and merge_state; fails if gh does.
view() {
    local json
    json="$(gh pr view "$pr" --json state,isDraft,baseRefName,headRefName,headRefOid,mergeStateStatus 2>/dev/null)" || return 1
    { read -r state; read -r draft; read -r base; read -r branch; read -r head; read -r merge_state; } < <(
        jq -r '.state, .isDraft, .baseRefName, .headRefName, .headRefOid, .mergeStateStatus' <<<"$json"
    )
}

# mergeStateStatus can lag behind a merge, so ask how the commits compare.
behind_by() { gh api "repos/{owner}/{repo}/compare/$base...$head" --jq .behind_by 2>/dev/null; }

# Sets checkout to the worktree that has the branch, or to a temporary one.
find_checkout() {
    local line path="" found=""
    while IFS= read -r line; do
        case "$line" in
            "worktree "*) path="${line#worktree }" ;;
            "branch refs/heads/$branch") [[ ! -d "$path" ]] || found="$path" ;;
        esac
    done < <(git worktree list --porcelain)
    if [[ -n "$found" ]]; then
        checkout="$found"
        return 0
    fi
    # Under target/: a test run builds there, and it is ignored by git.
    checkout="$root/target/merge-train/pr-$pr"
    mkdir -p "$(dirname "$checkout")"
    if git show-ref --verify --quiet "refs/heads/$branch"; then
        git worktree add -q "$checkout" "$branch" >"$log" 2>&1 || return 1
    else
        git fetch --quiet "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch" >"$log" 2>&1 || return 1
        git worktree add -q --track -b "$branch" "$checkout" "$remote/$branch" >"$log" 2>&1 || return 1
        temp_branch="$branch"
    fi
    temp_worktree="$checkout"
}

rebase_in_progress() {
    (
        cd "$checkout"
        [[ -d "$(git rev-parse --git-path rebase-merge)" || -d "$(git rev-parse --git-path rebase-apply)" ]]
    )
}

# `just update-branch` in the branch's checkout. Sets expected to the new head.
update_branch() {
    find_checkout || { show_log; stop "couldn't check out $branch"; }
    if rebase_in_progress; then
        stop "a rebase is in progress in $checkout; finish or abort it, then run the train again"
    fi
    if ! (
        cd "$checkout"
        [[ -z "$temp_worktree" ]] || export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
        just update-branch "$pr"
    ) >"$log" 2>&1 </dev/null; then
        if rebase_in_progress; then
            git -C "$checkout" rebase --abort >/dev/null 2>&1 || true
            git -C "$checkout" config --unset "branch.$branch.updateBranchRemoteTip" || true
            remove_temp_worktree
            stop "the rebase onto $base stopped on a conflict or a commit it could not sign; nothing was pushed. Run 'just update-branch $pr' from its checkout to resolve it"
        fi
        show_log
        remove_temp_worktree
        stop "just update-branch refused"
    fi
    expected="$(git -C "$checkout" rev-parse HEAD)"
    remove_temp_worktree
}

# Polls until every check has finished, every required one passed and nothing
# failed. Right after a push GitHub may still show the old head, or only some
# of the new one's checks, so green alone isn't enough.
wait_for_checks() {
    local start="$SECONDS" checks failed pending required missing check bucket
    while :; do
        if view; then
            if [[ "$head" == "$expected" ]]; then
                rebased=0
            elif [[ "$rebased" == 0 ]]; then
                stop "head moved to ${head:0:12} during the wait; someone else pushed to it"
            fi
            # gh exits non-zero while checks are pending, and on a network error.
            checks="$(gh pr checks "$pr" --json name,bucket 2>/dev/null || true)"
            if [[ "$rebased" == 0 ]] && jq -e 'type == "array"' <<<"$checks" >/dev/null 2>&1; then
                failed="$(jq -r '[.[] | select(.bucket == "fail" or .bucket == "cancel") | .name] | join(", ")' <<<"$checks")"
                [[ -z "$failed" ]] || stop "failed checks: $failed"
                pending="$(jq -r '[.[] | select(.bucket == "pending")] | length' <<<"$checks")"
                missing=0
                required=0
                while IFS= read -r check; do
                    [[ -z "$check" || "$check" == \#* ]] && continue
                    required=1
                    bucket="$(jq -r --arg n "$check" '[.[] | select(.name == $n)][0].bucket // "missing"' <<<"$checks")"
                    [[ "$bucket" == "pass" ]] || missing=1
                done <"$root/.github/required-checks.txt"
                if [[ "$pending" == 0 && "$missing" == 0 && "$required" == 1 ]]; then
                    return 0
                fi
            fi
        fi
        if ((SECONDS - start >= timeout_secs)); then
            stop "timed out after ${timeout_secs}s waiting for checks"
        fi
        sleep "$poll_secs"
    done
}

# Everything for one PR, ending in `just merge`.
run_pr() {
    local round behind
    for ((round = 1; round <= max_rounds; round++)); do
        view || stop "gh pr view failed"
        [[ "$state" == "OPEN" ]] || stop "PR is $state"
        [[ "$draft" == "false" ]] || stop "PR is a draft"
        [[ "$merge_state" != "DIRTY" ]] || stop "branch has merge conflicts with $base; run 'just update-branch $pr' from its checkout to resolve them"
        behind="$(behind_by)" || stop "couldn't compare the branch with $base"
        expected="$head"
        rebased=0
        if [[ "$behind" == 0 ]]; then
            step update-branch "not behind"
        else
            update_branch
            rebased=1
            head="$expected"
            step update-branch "rebased onto $base"
        fi
        wait_for_checks
        step checks green
        behind="$(behind_by)" || stop "couldn't compare the branch with $base"
        if [[ "$behind" == 0 ]]; then
            if ! just merge "$pr" >"$log" 2>&1 </dev/null; then
                show_log
                stop "just merge refused"
            fi
            step merge merged
            return 0
        fi
        step checks "main moved during the wait"
    done
    stop "main kept moving; it moved during each of $max_rounds waits"
}

remaining=("$@")
for ((i = 0; i < ${#remaining[@]}; i++)); do
    pr="${remaining[i]}"
    head=""
    later=""
    for next in "${remaining[@]:i+1}"; do
        later+=" #$next"
    done
    run_pr
done
echo "merge-train: merged:$(printf ' #%s' "${remaining[@]}")"
