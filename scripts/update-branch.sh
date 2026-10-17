#!/usr/bin/env bash
# Bring a PR branch up to date with its base by rebasing locally and
# re-signing every commit, then push it.
#
# Why not GitHub's "Update branch" button or `gh pr update-branch --rebase`:
# GitHub rewrites the commits without your signature, and the `main` ruleset
# requires signed commits, so the PR can't merge afterwards.
#
# Run it from a checkout or worktree of the PR's head branch with a clean
# tree. On conflicts it stops and tells you how to continue; it never
# resolves anything itself.
#
# usage: scripts/update-branch.sh <pr-number>
set -euo pipefail

# Hooks and wrappers export these; they would point git at the wrong repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

pr="${1:?usage: just update-branch <pr-number>}"
remote="${AC_REMOTE:-origin}"
fail() { echo "update-branch: $*" >&2; exit 1; }

pr_json="$(gh pr view "$pr" --json state,headRefName,baseRefName,isCrossRepository)"
field() { jq -r "$1" <<<"$pr_json"; }

[[ "$(field .state)" == "OPEN" ]] || fail "PR #$pr is $(field .state)"
[[ "$(field .isCrossRepository)" == "false" ]] || fail "PR #$pr comes from a fork; update it from the fork's checkout"
branch="$(field .headRefName)"
base="$(field .baseRefName)"

git_dir="$(git rev-parse --git-dir)"
if [[ -d "$git_dir/rebase-merge" || -d "$git_dir/rebase-apply" ]]; then
    fail "a rebase is already in progress; finish it (git rebase --continue) or abort it (git rebase --abort), then re-run"
fi

current="$(git rev-parse --abbrev-ref HEAD)"
[[ "$current" == "$branch" ]] \
    || fail "PR #$pr is branch '$branch' but this checkout is on '$current'; switch to it (git switch $branch) or run this from that worktree"
[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean; commit or stash your changes first"

git fetch --quiet "$remote"
prev="$(git rev-parse --verify --quiet "refs/remotes/$remote/$branch")" \
    || fail "$remote/$branch does not exist; push the branch first (just pr)"
git rev-parse --verify --quiet "refs/remotes/$remote/$base" >/dev/null \
    || fail "$remote/$base does not exist"

# Never overwrite remote commits we haven't got locally.
# After a rebase that stopped on conflicts the old remote tip is no longer an
# ancestor of HEAD, so the tip recorded before the rebase started is accepted
# as long as the remote still points at it.
marker="branch.$branch.updateBranchRemoteTip"
if ! git merge-base --is-ancestor "$prev" HEAD && [[ "$(git config --get "$marker" || true)" != "$prev" ]]; then
    fail "$remote/$branch has commits that are not in your local branch; pull them first"
fi
git config "$marker" "$prev"

# Every commit ahead of base needs a good signature (G = good, U = good but the
# key isn't locally trusted). Anything else would be blocked by the ruleset.
unsigned_commits() {
    git log --format='%h %G?' "refs/remotes/$remote/$base..HEAD" | awk '$2 != "G" && $2 != "U"'
}

if git merge-base --is-ancestor "refs/remotes/$remote/$base" HEAD && [[ -z "$(unsigned_commits)" ]]; then
    echo "already based on $remote/$base and fully signed"
elif ! git rebase --force-rebase --exec 'git commit --amend --no-edit -S' "refs/remotes/$remote/$base"; then
    printf '%s\n' \
        "" \
        "update-branch: rebase stopped (conflicts, or a commit could not be signed)." \
        "  1. Resolve the conflicts and 'git add' the files." \
        "  2. git rebase --continue   (the remaining commits are re-signed as they replay)" \
        "  3. just update-branch $pr  (verifies signatures and pushes)" \
        "To give up: git rebase --abort" >&2
    exit 1
fi

bad="$(unsigned_commits)"
if [[ -n "$bad" ]]; then
    echo "$bad" >&2
    fail "the commits above are not signed; check user.signingkey and gpg-agent, then re-run"
fi

if [[ "$(git rev-parse HEAD)" == "$prev" ]]; then
    git config --unset "$marker"
    echo "nothing to push; $branch is at $(git rev-parse --short HEAD)"
    exit 0
fi

git push "--force-with-lease=refs/heads/$branch:$prev" "$remote" "HEAD:refs/heads/$branch"
git config --unset "$marker"
echo "updated $branch; new head $(git rev-parse HEAD)"
