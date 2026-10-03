"""AI narration over exploit findings.

Two jobs, both pure narration over already-recorded results:

  remediation_for(finding)  turn static FINDING_META text into contextual advice
  summary_for(findings)     a short narrative for the dashboard

Design rule (see docs/EXPLOIT_AI_ROADMAP.md): **AI narrates and correlates; it
never decides scope or authority.** The exploit engine's scope gates, triage
caps and outcome taxonomy stay deterministic. Everything here is advisory,
labelled as AI-generated, and fail-open — an AI error must never block a page
render. The static `FINDING_META` text remains the source of truth and is
always shown alongside the AI wording.
"""

from __future__ import annotations

import json
import re
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Cache: one entry per finding key / summary window. Bounded, on disk, so a
# Pi Zero-class board does not re-pay the model on every page load.
_CACHE_FILE = "data/exploits/ai_insights_cache.json"
_CACHE_TTL = 12 * 3600        # remediation
_SUMMARY_TTL = 30 * 60        # dashboard summary
_CACHE_MAX = 2000


def _cache_path() -> Path:
    return Path(__file__).resolve().parents[1] / _CACHE_FILE


def _cache_load() -> Dict[str, Any]:
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _cache_save(data: Dict[str, Any]) -> None:
    try:
        p = _cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        if len(data) > _CACHE_MAX:
            for k in sorted(data, key=lambda x: data[x].get("ts", 0))[:500]:
                data.pop(k, None)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(p)
    except Exception as exc:
        logger.debug("ai_insights cache write failed: %s", exc)


def _service(shared_data):
    """Return a working AIService, or None. Never raises.

    Three things have to hold: the shared_data must carry a service (or be
    able to build one), that service must import cleanly, and it must report
    itself enabled. SharedData.initialise_ai_service() nulls `ai_service` when
    the import fails at startup - notably when `openai` is broken - so a
    None here is the common case and we retry rather than give up. Failures
    are logged at WARNING: a silent DEBUG here is what makes "AI is
    configured but does nothing" so hard to diagnose.
    """
    # Memoise the outcome, including failure. Without this every AI panel
    # request re-runs the whole resolution path - we logged 44
    # "Failed to initialize AI service" lines in 20 minutes from a single
    # page's worth of calls.
    memo = getattr(shared_data, "_ai_insights_memo", None)
    if memo is not None:
        return memo.get("svc")

    def _remember(svc):
        try:
            shared_data._ai_insights_memo = {"svc": svc}
        except Exception:
            pass
        return svc

    try:
        svc = getattr(shared_data, "ai_service", None)
        if svc is not None and _svc_usable(svc):
            return _remember(svc)

        # Retry the app's own initialiser first - it knows the config shape.
        init = getattr(shared_data, "initialize_ai_service", None)
        if callable(init):
            try:
                init()
                svc = getattr(shared_data, "ai_service", None)
                if svc is not None and _svc_usable(svc):
                    return _remember(svc)
            except Exception as exc:
                logger.warning("ai_insights: shared init failed: %s", exc)

        from ai_service import AIService
        svc = AIService(shared_data)
        if _svc_usable(svc):
            return _remember(svc)
        logger.warning("ai_insights: AI service present but not enabled "
                       "(check ai_enabled / ai_model / the API token)")
        return _remember(None)
    except Exception as exc:
        logger.warning("ai_insights: no AI service available: %s", exc)
        return _remember(None)


def _svc_usable(svc) -> bool:
    """True when the service can actually answer. Never raises."""
    try:
        return bool(svc.is_enabled())
    except Exception:
        return False


def _enabled(shared_data, key: str, default: bool = True) -> bool:
    try:
        return bool(shared_data.config.get(key, default))
    except Exception:
        return default


def _finding_key(f: Dict[str, Any]) -> str:
    return "%s|%s|%s|%s" % (f.get("ip", ""), f.get("port", ""),
                            f.get("cve_id", "-"), f.get("poc_id", "") or f.get("detail", ""))


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

_REMEDIATION_SYSTEM = (
    "You are a senior network security engineer writing remediation guidance "
    "for a home-lab operator. Be concrete and specific to the host described. "
    "Give the exact command, config line, or patch where you can. Keep it under "
    "90 words. Do not restate the finding. Do not invent CVEs or severity. "
    "Answer with the guidance text only - no preamble, no markdown headers."
)


def remediation_for(finding: Dict[str, Any], shared_data=None,
                    host_context: str = "") -> Dict[str, Any]:
    """Return AI-refined remediation for one finding.

    Always includes the static `remediation` from FINDING_META as the source of
    truth. The AI text is a refinement, not a replacement. Fail-open: any error
    returns the static text alone with `ai=None`.
    """
    static = finding.get("remediation") or ""
    out = {"static": static, "ai": None, "cached": False, "generated": None}
    if shared_data is None or not _enabled(shared_data, "exploit_ai_remediation", True):
        return out

    key = "rem:" + _finding_key(finding)
    cache = _cache_load()
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < _CACHE_TTL:
        out["ai"] = hit.get("text")
        out["cached"] = True
        out["generated"] = hit.get("ts")
        return out

    svc = _service(shared_data)
    if svc is None or not svc.is_enabled():
        return out

    user = (
        f"Host: {finding.get('ip')}:{finding.get('port')}\n"
        f"Finding: {finding.get('title') or finding.get('cve_id')}\n"
        f"CVE: {finding.get('cve_id')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Evidence: {(finding.get('evidence') or '')[:300]}\n"
        f"How we know: {(finding.get('how') or '')[:300]}\n"
        f"Baseline remediation: {static[:300]}\n"
    )
    if host_context:
        user += f"Host context: {host_context[:300]}\n"

    try:
        reply = (svc._ask(_REMEDIATION_SYSTEM, user) or "").strip()
    except Exception as exc:
        logger.debug("ai remediation failed: %s", exc)
        return out
    if not reply:
        return out

    out["ai"] = reply[:600]
    out["generated"] = time.time()
    cache[key] = {"text": out["ai"], "ts": out["generated"]}
    _cache_save(cache)
    return out


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------

_SUMMARY_SYSTEM = (
    "You are writing a one-paragraph security status summary for a homelab "
    "monitoring dashboard. Be concrete and prioritised: lead with the most "
    "important finding, then say what is clean. Mention specific hosts and "
    "CVEs. Maximum 90 words. No preamble, no bullet lists, no markdown. "
    "If there are no findings say so plainly and note the coverage."
)


def summary_for(findings: List[Dict[str, Any]], shared_data=None,
                window: str = "recent") -> Dict[str, Any]:
    """Return a short narrative over the findings ledger.

    Fail-open to a plain deterministic sentence when AI is unavailable, so the
    dashboard always has something to show.
    """
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("outcome", "skipped")] = counts.get(f.get("outcome", "skipped"), 0) + 1
    vulns = [f for f in findings if f.get("outcome") == "vulnerable"]
    hosts = sorted({f.get("ip") for f in findings if f.get("ip")})

    fallback = (
        f"{counts.get('vulnerable', 0)} vulnerable across {len(hosts)} host(s); "
        f"{counts.get('not_vulnerable', 0)} checks clean, "
        f"{counts.get('skipped', 0)} skipped."
    )
    out = {"text": fallback, "ai": False, "cached": False, "generated": None}

    if shared_data is None or not _enabled(shared_data, "ai_exploit_summary", True):
        return out

    key = f"sum:{window}:{len(findings)}:{counts.get('vulnerable', 0)}"
    cache = _cache_load()
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < _SUMMARY_TTL:
        out["text"] = hit.get("text")
        out["ai"] = True
        out["cached"] = True
        out["generated"] = hit.get("ts")
        return out

    svc = _service(shared_data)
    if svc is None or not svc.is_enabled():
        return out

    lines = []
    for f in vulns[:6]:
        lines.append(f"- {f.get('ip')}:{f.get('port')} {f.get('title') or f.get('cve_id')} "
                     f"[{f.get('severity')}] {(f.get('evidence') or '')[:80]}")
    user = (
        f"Findings in scope: {len(findings)} total across {len(hosts)} host(s). "
        f"Outcome counts: {counts}.\\n"
        f"Confirmed vulnerable:\\n" + ("\\n".join(lines) if lines else "(none)") + "\\n"
    )

    try:
        reply = (svc._ask(_SUMMARY_SYSTEM, user) or "").strip()
    except Exception as exc:
        logger.debug("ai summary failed: %s", exc)
        return out
    if not reply:
        return out

    out["text"] = reply[:500]
    out["ai"] = True
    out["generated"] = time.time()
    cache[key] = {"text": out["text"], "ts": out["generated"]}
    _cache_save(cache)
    return out


# ---------------------------------------------------------------------------
# Tier 2 (1): correlate findings with captured credentials
# ---------------------------------------------------------------------------

def _load_credentials() -> List[Dict[str, Any]]:
    """Captured (service, ip, user) tuples from the loot CSVs.

    The connector modules write one CSV per service under
    data/networks/<net>/loot/credentials/. Header row only means nothing has
    been captured yet, which is fine - correlation is still worth building so
    it lights up the moment a capture lands.
    """
    out: List[Dict[str, Any]] = []
    root = Path(__file__).resolve().parents[1] / "data" / "networks"
    if not root.is_dir():
        return out
    try:
        import csv
        for f in sorted(root.glob("*/loot/credentials/*.csv")):
            svc = f.stem.lower()
            try:
                with f.open(newline="", encoding="utf-8", errors="replace") as fh:
                    for row in csv.DictReader(fh):
                        ip = (row.get("IP Address") or row.get("ip") or "").strip()
                        user = (row.get("User") or row.get("username") or "").strip()
                        if ip:
                            out.append({"service": svc, "ip": ip,
                                        "user": user, "source": str(f)})
            except Exception:
                continue
    except Exception as exc:
        logger.debug("credential load failed: %s", exc)
    return out


_CORR_SYSTEM = (
    "You are a network security analyst writing a lateral-movement assessment "
    "for a homelab operator. Given confirmed exploit findings and captured "
    "credentials, describe concrete attack paths an adversary on this LAN could "
    "take. Be specific about which host is the pivot and why. Name the CVE and "
    "the service. Maximum 90 words. No preamble, no markdown headers. If the "
    "credentials and findings do not combine into a real path, say so plainly "
    "rather than inventing one."
)


def correlate_for(findings: List[Dict[str, Any]], shared_data=None,
                  credentials: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Lateral-movement hypotheses from findings + captured credentials.

    Fail-open to a deterministic summary when AI is unavailable. Framed as
    hypothesis, never as fact - these are correlations, not proven paths.
    """
    creds = credentials if credentials is not None else _load_credentials()
    vulns = [f for f in findings if f.get("outcome") == "vulnerable"]
    cred_hosts = sorted({c["ip"] for c in creds})
    vuln_hosts = sorted({f.get("ip") for f in vulns if f.get("ip")})

    fallback_parts = []
    if creds and vulns:
        both = sorted(set(cred_hosts) & set(vuln_hosts))
        if both:
            fallback_parts.append(f"{len(both)} host(s) have both credentials and findings")
        else:
            fallback_parts.append(
                f"{len(cred_hosts)} host(s) with captured credentials, "
                f"{len(vuln_hosts)} with findings - no direct overlap")
    elif creds:
        fallback_parts.append(f"{len(cred_hosts)} host(s) with captured credentials, no findings yet")
    elif vulns:
        fallback_parts.append(f"{len(vuln_hosts)} host(s) with findings, no credentials captured yet")
    else:
        fallback_parts.append("No credentials captured and no confirmed findings")
    fallback = ". ".join(fallback_parts) + "."

    out = {"text": fallback, "ai": False, "cached": False,
           "credential_hosts": cred_hosts, "finding_hosts": vuln_hosts,
           "overlap": sorted(set(cred_hosts) & set(vuln_hosts))}

    if shared_data is None or not _enabled(shared_data, "ai_exploit_correlate", True):
        return out
    if not creds and not vulns:
        return out

    key = f"corr:{len(creds)}:{len(vulns)}:{len(set(cred_hosts) & set(vuln_hosts))}"
    cache = _cache_load()
    hit = cache.get(key)
    if hit and time.time() - hit.get("ts", 0) < _SUMMARY_TTL:
        out["text"] = hit.get("text"); out["ai"] = True; out["cached"] = True
        return out

    svc = _service(shared_data)
    if svc is None or not svc.is_enabled():
        return out

    cred_lines = [f"- {c["service"]} {c["ip"]} user={c["user"] or '?'}" for c in creds[:20]]
    vuln_lines = [f"- {f.get('ip')}:{f.get('port')} {f.get('title') or f.get('cve_id')} [{f.get('severity')}]"
                  for f in vulns[:12]]
    user = (
        "CAPTURED CREDENTIALS:\n" + ("\n".join(cred_lines) if cred_lines else "(none)") + "\n\n"
        "CONFIRMED FINDINGS:\n" + ("\n".join(vuln_lines) if vuln_lines else "(none)")
    )
    try:
        reply = (svc._ask(_CORR_SYSTEM, user) or "").strip()
    except Exception as exc:
        logger.debug("ai correlation failed: %s", exc)
        return out
    if not reply:
        return out
    out["text"] = reply[:600]; out["ai"] = True; out["generated"] = time.time()
    cache[key] = {"text": out["text"], "ts": out["generated"]}
    _cache_save(cache)
    return out


# ---------------------------------------------------------------------------
# Tier 2 (2): trending / regression detection
# ---------------------------------------------------------------------------

def trend_for(current: List[Dict[str, Any]],
              previous: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Diff two findings snapshots: new / resolved / regressed / stable.

    Purely deterministic - no model call. Keyed on (ip, port, cve_id, poc_id)
    so a re-scan of the same host does not look like churn. Cheap enough to run
    on every dashboard refresh.
    """
    def key(f):
        return (f.get("ip", ""), str(f.get("port")), f.get("cve_id", "-"),
                f.get("poc_id", "") or f.get("detail", ""))

    def outcome(f):
        return (f.get("outcome") or "").lower()

    cur = {}
    for f in current:
        cur.setdefault(key(f), f)
    prev = {}
    for f in previous:
        prev.setdefault(key(f), f)

    new = [f for k, f in cur.items() if k not in prev and outcome(f) == "vulnerable"]
    resolved = [f for k, f in prev.items() if k not in cur and outcome(f) == "vulnerable"]
    # regressed: same key, was clean, now vulnerable
    regressed = [f for k, f in cur.items()
                 if k in prev and outcome(f) == "vulnerable"
                 and outcome(prev[k]) in ("not_vulnerable", "skipped", "error")]
    stable = [f for k, f in cur.items()
              if k in prev and outcome(f) == "vulnerable"
              and outcome(prev[k]) == "vulnerable"]

    return {
        "new": [{"ip": f.get("ip"), "port": f.get("port"),
                 "title": f.get("title"), "severity": f.get("severity")} for f in new],
        "resolved": [{"ip": f.get("ip"), "port": f.get("port"),
                      "title": f.get("title")} for f in resolved],
        "regressed": [{"ip": f.get("ip"), "port": f.get("port"),
                       "title": f.get("title"), "severity": f.get("severity")} for f in regressed],
        "stable": len(stable),
        "checked": len(cur),
    }


# ---------------------------------------------------------------------------
# Tier 3 (1): natural-language Q&A over findings
# ---------------------------------------------------------------------------

_ASK_SYSTEM = (
    "You are a security analyst answering a homelab operator's question about "
    "their network. Answer ONLY from the supplied findings and statistics. "
    "Be specific - name hosts, CVEs, ports. If the data does not answer the "
    "question, say so plainly and say what scan would. Maximum 120 words. "
    "No markdown headers, no bullet lists unless the question is a list."
)


def answer_for(question: str, findings: List[Dict[str, Any]],
               shared_data=None, max_findings: int = 40) -> Dict[str, Any]:
    """Answer a natural-language question over the findings ledger.

    Fail-open to a deterministic fallback. `max_findings` bounds the prompt so
    a Pi-class board can still serve the request - the worst findings go in
    first, since those are what an operator is actually asking about.
    """
    q = (question or "").strip()
    out = {"question": q, "text": "", "ai": False, "used_findings": 0}
    if not q:
        out["text"] = "Ask a question about the findings."
        return out

    # Worst-first: vulnerabilities, then by severity, then newest.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(
        findings,
        key=lambda f: (
            0 if f.get("outcome") == "vulnerable" else 1,
            sev_rank.get((f.get("severity") or "info").lower(), 5),
            -float(f.get("ts") or 0),
        ),
    )
    subset = ranked[:max(1, int(max_findings))]
    out["used_findings"] = len(subset)

    vulns = [f for f in subset if f.get("outcome") == "vulnerable"]
    fallback = (
        f"{len(vulns)} confirmed vulnerable and {len(subset) - len(vulns)} other "
        f"results in scope. Enable the AI service for a natural-language answer."
    ) if vulns else (
        f"No confirmed vulnerabilities in the {len(subset)} results in scope. "
        f"Enable the AI service for a natural-language answer."
    )
    out["text"] = fallback

    if shared_data is None or not _enabled(shared_data, "ai_exploit_ask", True):
        return out
    svc = _service(shared_data)
    if svc is None or not svc.is_enabled():
        return out

    lines = []
    for f in subset:
        lines.append(
            f"- {f.get('ip')}:{f.get('port')} [{f.get('outcome')}] "
            f"{f.get('title') or f.get('cve_id')} ({f.get('severity')}) "
            f"{(f.get('evidence') or f.get('detail') or '')[:70]}"
        )
    user = (
        f"QUESTION: {q}\n\n"
        f"AVAILABLE FINDINGS ({len(subset)} of {len(findings)}, worst-first):\n"
        + "\n".join(lines)
    )
    try:
        reply = (svc._ask(_ASK_SYSTEM, user) or "").strip()
    except Exception as exc:
        logger.debug("ai ask failed: %s", exc)
        return out
    if reply:
        out["text"] = reply[:900]
        out["ai"] = True
    return out


# ---------------------------------------------------------------------------
# Tier 3 (2): AI-authored scan scheduling suggestions
# ---------------------------------------------------------------------------

_SCHEDULE_SYSTEM = (
    "You are a network security operations advisor. Based on observed network "
    "state, suggest scan-schedule and aggression changes for a homelab "
    "monitoring tool. You may suggest: scan_interval, scan_vuln_interval, "
    "nmap timing template (-T0..-T5), exploit_min_cvss, exploit_max_per_host, "
    "and exploit_nuclei_concurrency. Return ONLY a JSON object mapping config "
    "key -> proposed value, with a short 'why' for each. Never suggest removing "
    "scope guardrails (exploit_allow_all, exploit_allow_external) or disabling "
    "the allowlist - those are safety controls. If nothing should change, "
    "return an empty object. No commentary outside the JSON."
)


def suggest_schedule(state: Dict[str, Any], shared_data=None) -> Dict[str, Any]:
    """Propose scan-schedule / aggression changes. SUGGESTIONS ONLY.

    Never applied automatically - the operator must confirm every change.
    Scope guardrails (exploit_allow_all, exploit_allow_external, allowlist)
    are stripped from any proposal the model returns; this function cannot
    weaken them.
    """
    # Hard safety: these keys are never editable through this path.
    FORBIDDEN = {
        "exploit_allow_all", "exploit_allow_external", "exploit_allowlist",
        "enable_attacks", "manual_mode", "scan_subnets",
    }
    out = {"proposals": {}, "reasons": {}, "ai": False, "raw": ""}
    if shared_data is None or not _enabled(shared_data, "ai_exploit_schedule", False):
        out["raw"] = "disabled"
        return out
    svc = _service(shared_data)
    if svc is None or not svc.is_enabled():
        out["raw"] = "ai unavailable"
        return out

    try:
        user = "OBSERVED STATE:\n" + json.dumps(state, default=str)[:3000]
        reply = (svc._ask(_SCHEDULE_SYSTEM, user) or "").strip()
        out["raw"] = reply[:2000]
    except Exception as exc:
        logger.debug("ai schedule failed: %s", exc)
        return out

    try:
        m = re.search(r"\{.*\}", reply, re.S)
        data = json.loads(m.group(0)) if m else {}
    except Exception:
        return out
    if not isinstance(data, dict):
        return out

    for k, v in data.items():
        if k in FORBIDDEN:
            continue
        if k == "why":
            continue
        out["proposals"][k] = v
    if isinstance(data.get("why"), dict):
        out["reasons"] = {k: str(v)[:200] for k, v in data["why"].items()}

    out["ai"] = True
    return out
