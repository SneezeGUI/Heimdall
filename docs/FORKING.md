# Maintaining Heimdall as a fork

Heimdall is a **patch-series fork** of [Ragnar](https://github.com/PierreGode/Ragnar),
which is itself a derivative of [Bjorn](https://github.com/infinition/Bjorn).

This document explains how the fork is structured so upstream sync stays
tractable as both projects move.

---

## The model

```
in-tree (permanent, never conflicts)
    actions/exploit_engine.py        exploit engine
    actions/exploit_action.py        ExploitRunner action
    actions/ai_credential_engine.py  AI credential engine
    notify_sinks.py                  ntfy / webhook sinks
    docs/                            docs

patches/ (small, re-applied on sync)
    0001-orchestrator-standalone-actions.patch
    0002-nmap-active-check-scripts.patch
    0003-display-exploit-stats.patch
    0004-shared-exploit-helpers.patch
    0005-webapp-exploit-endpoints.patch
    0006-web-dashboard-exploit-tile.patch
    0007-actions-json-exploit-runner.patch
```

Why patches and not a plain merge? Upstream's `webapp_modern.py` alone is
tens of thousands of lines. Our invasive surface is **~250 lines across 7
files**. Keeping those as an explicit series means a sync is "re-apply 7 small
diffs and fix the one that conflicts", not "merge a mountain and hope".

New features never go into a patch. If a feature needs to touch upstream code,
keep that touch as small as possible and let the bulk live in its own module.

---

## Syncing upstream

```bash
scripts/sync-upstream.sh
```

The script:

1. Fetches `PierreGode/Ragnar` `main`.
2. Reports how far apart you are and where the merge base is.
3. Tries a normal merge first — our work is real commits, so this often just
   works.
4. If the merge conflicts, falls back to checking out upstream and replaying
   `patches/*.patch` with `git apply --3way`.
5. Leaves any conflicted patch as a `.rej` file and **exits non-zero** rather
   than guessing.

It never pushes. Review, then decide.

### After resolving conflicts by hand

Regenerate the series so the next sync is clean:

```bash
scripts/refresh-patches.sh
git add patches/ && git commit -m "chore: refresh upstream patch series"
```

---

## Policy

* **We resolve conflicts** when upstream and Heimdall's features collide.
  Upstream is not obliged to accommodate us.
* **We share bugfixes upstream.** If we fix something that is wrong in
  Ragnar — a crash, a memory leak, a correctness bug — we open a PR against
  `PierreGode/Ragnar`. Feature work stays here.
* **We do not claim to be the official Ragnar.** Ragnar's canonical source is
  `https://github.com/PierreGode/Ragnar.git`. Heimdall is a continuation of the
  *Bjorn* lineage, credited in the README.
* **Attribution is never removed.** Both infinition (Bjorn) and Pierre Gode
  (Ragnar) are credited in `README.md` and `LICENSE`. See the LICENSE for the
  exact terms that govern each portion of the codebase.

---

## Where our changes live

| Area | Files | Nature |
|---|---|---|
| Exploit engine | `actions/exploit_engine.py`, `actions/exploit_action.py` | new module |
| AI credentials | `actions/ai_credential_engine.py`, `actions/connector_utils.py` | new module |
| Alerts | `notify_sinks.py` | new module |
| Installer | `install_ragnar.sh`, `scripts/` | new scripts |
| Core hooks | `orchestrator.py`, `webapp_modern.py`, `display.py`, `shared.py`, `actions/nmap_vuln_scanner.py`, `web/scripts/ragnar_modern.js`, `config/actions.json` | **patch series** |

If you add a new core-file hook, add it to the `SPECS` list in
`scripts/refresh-patches.sh` so it is tracked.

---

## Naming and identity

* **Product name:** Heimdall
* **Lineage:** Bjorn (infinition) → Ragnar (Pierre Gode) → Heimdall (SneezeGUI)
* **Internal code paths** still say `ragnar` in places (`/home/ragnar/Ragnar`,
  `ragnar.service`). A full rebrand is a separate, deliberate change — do not
  mix it into a sync or a feature commit.

---

## Licensing

Three sets of terms, each governing its own portions:

1. **Part A** — MIT License, original Bjorn-derived code (`infinition`).
2. **Part B** — Supplemental Terms, Ragnar Contributions (`Pierre Gode`),
   retained verbatim and unmodified.
3. **Part C** — Supplemental Terms, Heimdall Contributions (`SneezeGUI`).

No part relicenses another. In short: free for personal, educational, research
and internal non-commercial use with attribution retained; not for sale as a
product. See [`LICENSE`](../LICENSE).
