"""Declared intent, and the drift report that compares it against reality.

An intent file states what humans *believe* the policies do. The engine states
what they *actually* do. Everywhere those two disagree is drift.

    rules:
      - name: frontend reaches api
        from: {namespace: prod, labels: {app: frontend}}
        to:   {namespace: prod, labels: {app: api}}
        port: 8080
        expect: allow
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .engine import Engine, Flow
from .model import Pod
from .selectors import matches_selector


@dataclass(frozen=True)
class Endpoint:
    namespace: str | None = None
    labels: dict[str, str] | None = None
    selector: dict[str, Any] | None = None

    def matches(self, pod: Pod) -> bool:
        if self.namespace is not None and pod.namespace != self.namespace:
            return False
        if self.labels is not None and not matches_selector(
            {"matchLabels": self.labels}, pod.labels
        ):
            return False
        if self.selector is not None and not matches_selector(self.selector, pod.labels):
            return False
        return True

    def describe(self) -> str:
        parts = []
        if self.namespace:
            parts.append(f"ns={self.namespace}")
        if self.labels:
            parts.append(",".join(f"{k}={v}" for k, v in sorted(self.labels.items())))
        if self.selector:
            parts.append("selector")
        return " ".join(parts) or "any pod"


@dataclass(frozen=True)
class IntentRule:
    name: str
    source: Endpoint
    dest: Endpoint
    port: int
    protocol: str = "TCP"
    expect: str = "allow"


@dataclass(frozen=True)
class Violation:
    rule: IntentRule
    flow: Flow

    @property
    def summary(self) -> str:
        verb = "is denied but was expected to be allowed"
        if self.rule.expect == "deny":
            verb = "is allowed but was expected to be denied"
        return (
            f"{self.flow.src.ref} -> {self.flow.dst.ref} "
            f"{self.flow.protocol}/{self.flow.port} {verb}"
        )


@dataclass
class DriftReport:
    checked: int = 0
    matched_pairs: int = 0
    violations: list[Violation] = None  # type: ignore[assignment]
    empty_rules: list[IntentRule] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.violations = self.violations or []
        self.empty_rules = self.empty_rules or []

    @property
    def ok(self) -> bool:
        return not self.violations and not self.empty_rules


def load_intent(path: str | Path) -> list[IntentRule]:
    doc = yaml.safe_load(Path(path).read_text()) or {}
    return [_rule(raw, i) for i, raw in enumerate(doc.get("rules") or [])]


def _rule(raw: dict[str, Any], index: int) -> IntentRule:
    expect = str(raw.get("expect", "allow")).lower()
    if expect not in {"allow", "deny"}:
        raise ValueError(f"rule {index}: expect must be 'allow' or 'deny', got {expect!r}")
    if "port" not in raw:
        raise ValueError(f"rule {index}: 'port' is required")
    return IntentRule(
        name=raw.get("name") or f"rule[{index}]",
        source=_endpoint(raw.get("from") or {}),
        dest=_endpoint(raw.get("to") or {}),
        port=int(raw["port"]),
        protocol=str(raw.get("protocol", "TCP")).upper(),
        expect=expect,
    )


def _endpoint(raw: dict[str, Any]) -> Endpoint:
    return Endpoint(
        namespace=raw.get("namespace"),
        labels=dict(raw["labels"]) if raw.get("labels") else None,
        selector=raw.get("selector"),
    )


def verify(engine: Engine, rules: Iterable[IntentRule]) -> DriftReport:
    report = DriftReport()
    pods = engine.cluster.pods

    for rule in rules:
        report.checked += 1
        sources = [p for p in pods if rule.source.matches(p)]
        dests = [p for p in pods if rule.dest.matches(p)]
        pairs = [(s, d) for s in sources for d in dests if s is not d]

        if not pairs:
            report.empty_rules.append(rule)
            continue

        for src, dst in pairs:
            report.matched_pairs += 1
            flow = engine.flow(src, dst, rule.port, rule.protocol)
            if (rule.expect == "allow") != flow.allowed:
                report.violations.append(Violation(rule=rule, flow=flow))

    return report
