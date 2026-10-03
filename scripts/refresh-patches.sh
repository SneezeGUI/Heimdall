#!/usr/bin/env bash
# refresh-patches.sh — regenerate patches/*.patch from the current tree.
#
# Run after resolving a sync conflict by hand. Each upstream-facing file gets
# one patch, so the next sync only has to re-resolve the file that actually
# changed upstream. New files (actions/exploit_*.py, docs/) are deliberately
# NOT patched — they live in-tree and never conflict.

set -euo pipefail

PATCH_DIR="${PATCH_DIR:-patches}"
BASE_REF="${BASE_REF:-$(git merge-base HEAD origin/main 2>/dev/null || true)}"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[ -n "$BASE_REF" ] || die "cannot determine merge base — set BASE_REF="
command -v git >/dev/null || die "git not found"

# Order matters only for human readability; git apply is per-file so any order works.
declare -a SPECS=(
  "orchestrator.py|orchestrator-standalone-actions|standalone dispatch"
  "actions/nmap_vuln_scanner.py|nmap-active-check-scripts|active-check NSE + banners"
  "display.py|display-exploit-stats|e-ink exploit stats"
  "shared.py|shared-exploit-helpers|dashboard stat helpers"
  "webapp_modern.py|webapp-exploit-endpoints|API exploit fields"
  "web/scripts/ragnar_modern.js|web-dashboard-exploit-tile|dashboard tile + live update"
  "wifi_defense.py|wifi-monitor-adapter-selection|never monitor on the uplink radio"
  "config/actions.json|actions-json-exploit-runner|ExploitRunner registry"
)

info "merge base: $(git log -1 --format='%h %s' "$BASE_REF")"
rm -f "$PATCH_DIR"/[0-9]*.patch
mkdir -p "$PATCH_DIR"

n=1
total=0
for spec in "${SPECS[@]}"; do
  IFS='|' read -r file slug desc <<<"$spec"
  if [ ! -f "$file" ]; then
    echo "  skip  $file (absent)"
    continue
  fi
  if git diff --quiet "$BASE_REF" HEAD -- "$file" 2>/dev/null; then
    echo "  skip  $file (matches upstream)"
    continue
  fi
  out=$(printf "%s/%04d-%s.patch" "$PATCH_DIR" "$n" "$slug")
  git diff "$BASE_REF" HEAD -- "$file" > "$out"
  lines=$(grep -c '^[+-][^+-]' "$out" || true)
  echo "  write $out  ($lines changed lines — $desc)"
  total=$((total + lines))
  n=$((n + 1))
done

echo
info "$((n - 1)) patch(es), $total changed lines total"
echo "Commit these alongside any resolution:"
echo "    git add $PATCH_DIR && git commit -m 'chore: refresh upstream patch series'"
