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
