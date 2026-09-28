#!/usr/bin/env bash
# sync-upstream.sh — pull PierreGode/Ragnar main into Heimdall.
#
# Model: Heimdall is a patch-series fork. New features live in-tree; small
# edits to upstream's core files are kept in patches/*.patch so a sync is a
# per-file re-application rather than a blind merge of a 27k-line module.
#
# This script NEVER pushes. It only fetches and prepares a working tree.

set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/PierreGode/Ragnar.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
PATCH_DIR="${PATCH_DIR:-patches}"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }

command -v git >/dev/null || die "git not found"

# --- 1. remote ------------------------------------------------------------
if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  info "adding remote '$UPSTREAM_REMOTE' -> $UPSTREAM_URL"
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

info "fetching $UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
git fetch --no-tags "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" || die "fetch failed"

UP_HEAD="$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
BASE=$(git merge-base HEAD "$UP_HEAD") || die "no merge base with $UP_HEAD"

BEHIND=$(git rev-list --count HEAD.."$UP_HEAD")
AHEAD=$(git rev-list --count "$UP_HEAD"..HEAD)
info "divergence: $BEHIND upstream commit(s) missing, $AHEAD local commit(s) ahead"
info "merge base: $(git log -1 --format='%h %ad %s' --date=short "$BASE")"

if [ "$BEHIND" -eq 0 ]; then
  info "already up to date with upstream"
  exit 0
fi

# --- 2. clean tree check --------------------------------------------------
if ! git diff --quiet || ! git diff --cached --quiet; then
  die "working tree is dirty — commit or stash before syncing"
fi

# --- 3. attempt a plain merge first ---------------------------------------
# Our in-tree work is real commits, so a merge usually Just Works. The patch
# series is the fallback when upstream rewrote one of our core files.
info "attempting merge of $UP_HEAD (ours = Heimdall)"
if git merge --no-commit --no-ff "$UP_HEAD"; then
  info "merge applied cleanly"
  if ! git diff --quiet; then
    info "unmerged paths present — resolving via patch series"
    git merge --abort >/dev/null 2>&1 || true
    goto_patches=1
  else
    git commit -q -m "Merge $UP_HEAD into Heimdall

Brought upstream fixes and features into the fork. Heimdall's additions are
kept; attribution to Bjorn and Ragnar is unchanged."
    info "sync complete — review with 'git log --oneline -20' and 'git diff HEAD@{1}'"
    exit 0
  fi
else
  warn "merge had conflicts — falling back to patch series"
  git merge --abort >/dev/null 2>&1 || true
  goto_patches=1
fi

# --- 4. patch-series fallback --------------------------------------------
info "replaying local work on top of $UP_HEAD via patch series"
git checkout -B sync-tmp "$UP_HEAD" >/dev/null 2>&1

shopt -s nullglob
patches=("$PATCH_DIR"/[0-9]*.patch)
shopt -u nullglob

if [ ${#patches[@]} -eq 0 ]; then
  die "no patches found in $PATCH_DIR"
fi

info "applying ${#patches[@]} patch(es)"
failed=()
for p in "${patches[@]}"; do
  name=$(basename "$p")
  if git apply --3way --whitespace=nowarn "$p" 2>/dev/null; then
    echo "  ok    $name"
  elif git apply --reject --whitespace=nowarn "$p" 2>/dev/null; then
    echo "  PARTIAL $name (see *.rej)"
    failed+=("$name")
  else
    echo "  FAIL  $name"
    failed+=("$name")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo
  warn "${#failed[@]} patch(es) need manual resolution:"
  for f in "${failed[@]}"; do echo "    - $f"; done
  echo
  echo "Resolve the .rej files (or edit the targets by hand), then:"
  echo "    git add -A && git commit"
  echo "Finally regenerate the series so the next sync is clean:"
  echo "    scripts/refresh-patches.sh"
  exit 2
fi

git add -A
git commit -q -m "Rebase Heimdall onto $UP_HEAD

Upstream fixes pulled in; Heimdall's patch series re-applied on top."
info "sync complete on branch 'sync-tmp' — review, then:"
echo "    git checkout <your-main> && git merge sync-tmp"
