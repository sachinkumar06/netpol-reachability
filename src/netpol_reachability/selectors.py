"""Kubernetes LabelSelector evaluation.

An empty selector (`{}`) matches everything. A `None` selector is *not* the same
thing and is handled by the caller, because its meaning depends on context.
"""

from __future__ import annotations

from typing import Any


def matches_selector(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    if selector is None:
        return False
    if not selector:
        return True

    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False

    for expr in selector.get("matchExpressions") or []:
        if not _matches_expression(expr, labels):
            return False

    return True


def _matches_expression(expr: dict[str, Any], labels: dict[str, str]) -> bool:
    key = expr.get("key")
    operator = (expr.get("operator") or "").lower()
    values = {str(v) for v in (expr.get("values") or [])}
    present = key in labels
    actual = labels.get(key)

    if operator == "in":
        return present and actual in values
    if operator == "notin":
        return not present or actual not in values
    if operator == "exists":
        return present
    if operator == "doesnotexist":
        return not present
    raise ValueError(f"unsupported matchExpressions operator: {expr.get('operator')!r}")
