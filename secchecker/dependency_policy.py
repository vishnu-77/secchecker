"""Verdict policy for dependency scan findings — ALLOW / WARN / REVIEW / BLOCK.

Self-contained: this is *not* a reuse of firewall/policy.py's PolicyEngine.
That engine decides whether to redact-or-block a piece of LLM prompt/response
*text*; this decides what to do with a *package* given its static findings.
Different domain, same "small, table-driven, single responsibility" style.
"""
from typing import Dict, List, Literal, Optional

from secchecker.reporter import get_severity

Verdict = Literal['ALLOW', 'WARN', 'REVIEW', 'BLOCK']

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Default severity -> verdict thresholds. A package's verdict is driven by
# its single highest-severity finding. Configurable via dependency_scan
# config (see config.py) — these are the defaults when unset.
DEFAULT_THRESHOLDS: Dict[str, str] = {
    'block_at': 'CRITICAL',
    'review_at': 'HIGH',
    'warn_at': 'MEDIUM',
}


def highest_severity(findings):
    # type: (Dict[str, List[str]]) -> Optional[str]
    """Return the highest severity level among a package's findings, or
    None if there are no findings at all."""
    if not findings:
        return None
    levels = [get_severity(name) for name in findings]
    return max(levels, key=lambda lvl: SEVERITY_ORDER.get(lvl, 0))


def verdict_for(findings, thresholds=None):
    # type: (Dict[str, List[str]], Optional[Dict[str, str]]) -> Verdict
    """Map one package's findings dict ({pattern_name: [matches]}) to a
    verdict. Fail-safe: an unrecognised/missing threshold falls back to the
    corresponding DEFAULT_THRESHOLDS entry rather than silently allowing.
    """
    cfg = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        cfg.update({k: v for k, v in thresholds.items() if v})

    sev = highest_severity(findings)
    if sev is None:
        return 'ALLOW'

    level = SEVERITY_ORDER.get(sev, 0)
    block_min = SEVERITY_ORDER.get(cfg['block_at'], 3)
    review_min = SEVERITY_ORDER.get(cfg['review_at'], 2)
    warn_min = SEVERITY_ORDER.get(cfg['warn_at'], 1)

    if level >= block_min:
        return 'BLOCK'
    if level >= review_min:
        return 'REVIEW'
    if level >= warn_min:
        return 'WARN'
    return 'ALLOW'


def verdict_for_tree(results, thresholds=None):
    # type: (Dict[str, Dict[str, List[str]]], Optional[Dict[str, str]]) -> Verdict
    """Map a whole scan_directory_dependency() result (many files/packages)
    to a single overall verdict — the worst verdict of any individual file
    wins, matching how a CI gate should behave (one bad package blocks the
    install, not just gets averaged away)."""
    order: List[Verdict] = ['ALLOW', 'WARN', 'REVIEW', 'BLOCK']
    worst = 'ALLOW'  # type: Verdict
    for findings in results.values():
        v = verdict_for(findings, thresholds)
        if order.index(v) > order.index(worst):
            worst = v
    return worst
