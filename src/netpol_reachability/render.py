"""Output formats. No third-party rendering dependencies on purpose."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence

from .engine import Flow
from .intent import DriftReport

TICK = "allow"
CROSS = "DENY"


def flows_table(flows: Sequence[Flow], show_denied: bool = True) -> str:
    rows = [
        (
            f.src.ref,
            f.dst.ref,
            f"{f.protocol}/{f.port}",
            TICK if f.allowed else CROSS,
            _short_reason(f),
        )
        for f in flows
        if show_denied or f.allowed
    ]
    header = ("SOURCE", "DESTINATION", "PORT", "VERDICT", "WHY")
    return _table(header, rows)


def _short_reason(flow: Flow) -> str:
    if flow.allowed:
        parts = []
        if flow.egress.default_allow:
            parts.append("egress default-allow")
        else:
            parts.append("egress " + ",".join(flow.egress.allowing_policies))
        if flow.ingress.default_allow:
            parts.append("ingress default-allow")
        else:
            parts.append("ingress " + ",".join(flow.ingress.allowing_policies))
        return "; ".join(parts)

    if not flow.egress.allowed:
        return "egress blocked by " + ",".join(flow.egress.selecting_policies)
    return "ingress blocked by " + ",".join(flow.ingress.selecting_policies)


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    if not rows:
        return "(no flows)"
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(header)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)).rstrip())
    return "\n".join(lines)


def flows_json(flows: Iterable[Flow]) -> str:
    payload = [
        {
            "source": f.src.ref,
            "destination": f.dst.ref,
            "protocol": f.protocol,
            "port": f.port,
            "allowed": f.allowed,
            "egress": {
                "allowed": f.egress.allowed,
                "defaultAllow": f.egress.default_allow,
                "selectingPolicies": list(f.egress.selecting_policies),
                "allowingPolicies": list(f.egress.allowing_policies),
            },
            "ingress": {
                "allowed": f.ingress.allowed,
                "defaultAllow": f.ingress.default_allow,
                "selectingPolicies": list(f.ingress.selecting_policies),
                "allowingPolicies": list(f.ingress.allowing_policies),
            },
        }
        for f in flows
    ]
    return json.dumps(payload, indent=2)


def flows_mermaid(flows: Sequence[Flow]) -> str:
    lines = ["graph LR"]
    seen: set[str] = set()
    for f in flows:
        for pod in (f.src, f.dst):
            node = _node_id(pod.ref)
            if node not in seen:
                seen.add(node)
                lines.append(f'  {node}["{pod.ref}"]')
    for f in flows:
        if f.allowed:
            lines.append(
                f"  {_node_id(f.src.ref)} -->|{f.protocol}/{f.port}| {_node_id(f.dst.ref)}"
            )
    return "\n".join(lines)


def _node_id(ref: str) -> str:
    return ref.replace("/", "_").replace("-", "_").replace(".", "_")


def drift_text(report: DriftReport) -> str:
    lines: list[str] = []
    for rule in report.empty_rules:
        lines.append(
            f"UNMATCHED  {rule.name}: no pod pair matched "
            f"({rule.source.describe()} -> {rule.dest.describe()})"
        )
    for violation in report.violations:
        lines.append(f"DRIFT      {violation.rule.name}: {violation.summary}")
        for reason in violation.flow.reasons:
            lines.append(f"           {reason}")

    lines.append("")
    lines.append(
        f"{report.checked} intent rule(s), {report.matched_pairs} pod pair(s) evaluated, "
        f"{len(report.violations)} drift(s), {len(report.empty_rules)} unmatched."
    )
    lines.append("OK: policies match declared intent." if report.ok else "FAILED")
    return "\n".join(lines)


def drift_json(report: DriftReport) -> str:
    return json.dumps(
        {
            "ok": report.ok,
            "rulesChecked": report.checked,
            "pairsEvaluated": report.matched_pairs,
            "unmatchedRules": [r.name for r in report.empty_rules],
            "violations": [
                {
                    "rule": v.rule.name,
                    "expect": v.rule.expect,
                    "source": v.flow.src.ref,
                    "destination": v.flow.dst.ref,
                    "protocol": v.flow.protocol,
                    "port": v.flow.port,
                    "allowed": v.flow.allowed,
                    "reasons": list(v.flow.reasons),
                }
                for v in report.violations
            ],
        },
        indent=2,
    )
