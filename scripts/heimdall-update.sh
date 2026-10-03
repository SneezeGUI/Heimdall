#!/bin/bash
# heimdall-update - pull SneezeGUI/Heimdall and restart the service if it moved.
#
# This is OUR code, so no merge judgment is needed: fast-forward only, and if
# the local tree has been edited by hand we leave it alone rather than clobber
# the operator's work. Upstream (PierreGode) sync is a separate, manual step -
# see docs/FORKING.md.
set -u

REPO="${HEIMDALL_REPO:-https://github.com/SneezeGUI/Heimdall.git}"
BRANCH="${HEIMDALL_BRANCH:-main}"
DIR="${HEIMDALL_DIR:-/home/ragnar/Ragnar}"
LOG="${HEIMDALL_LOG:-/home/ragnar/heimdall-tools/update.log}"
SERVICE="${HEIMDALL_SERVICE:-ragnar}"

log() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

mkdir -p "$(dirname "$LOG")"
log "=== heimdall-update start ==="

cd "$DIR" 2>/dev/null || { log "repo missing at $DIR"; exit 1; }

if [ ! -d .git ]; then
    log "not a git checkout - skipping (install is not source-managed)"
    exit 0
fi

# Refuse to touch a tree with *tracked* local edits - someone is working here.
# Untracked runtime data and skip-worktree files are the app's own output and
# must never block an update. `git diff --name-only` is the only reliable
# signal: upstream ships a file literally named "-" (PR #812), and a
# porcelain-status grep choked on it, leaving a bare "-" and silently blocking
# every subsequent update.
DIRTY=$(git diff --name-only 2>/dev/null)
if [ -n "$DIRTY" ]; then
    log "tracked files modified - not pulling. Resolve or stash first:"
    printf '%s\n' "$DIRTY" | sed 's/^/    /' >> "$LOG"
    exit 0
fi

BEFORE=$(git rev-parse HEAD 2>/dev/null || echo none)

if ! git fetch --no-tags origin "$BRANCH" >> "$LOG" 2>&1; then
    log "fetch failed (offline?) - leaving install untouched"
    exit 0
fi

# Fast-forward only. Never a merge, never a rebase, never a reset.
if ! git merge --ff-only "origin/$BRANCH" >> "$LOG" 2>&1; then
    log "not a fast-forward - local and remote have diverged. Manual sync needed."
    exit 0
fi

AFTER=$(git rev-parse HEAD 2>/dev/null || echo none)
if [ "$BEFORE" = "$AFTER" ]; then
    log "already up to date ($AFTER)"
    exit 0
fi

log "updated $BEFORE -> $AFTER"
log "  $(git log -1 --format='%h %s')"

# Only restart if the service exists and something changed.
if systemctl list-unit-files "${SERVICE}.service" >/dev/null 2>&1; then
    if systemctl restart "$SERVICE" >> "$LOG" 2>&1; then
        log "restarted ${SERVICE}.service"
    else
        log "WARNING: restart of ${SERVICE}.service failed - check systemctl status"
    fi
fi

log "=== heimdall-update done ==="
