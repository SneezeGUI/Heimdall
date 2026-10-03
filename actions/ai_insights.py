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
    """Return the shared AIService, or None. Never raises."""
    try:
        svc = getattr(shared_data, "ai_service", None)
        if svc is not None:
            return svc
        from ai_service import AIService
        return AIService(shared_data)
    except Exception as exc:
        logger.debug("ai_insights: no AI service (%s)", exc)
        return None


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
