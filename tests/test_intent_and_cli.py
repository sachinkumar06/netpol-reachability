from __future__ import annotations

import json
from pathlib import Path

import pytest

from netpol_reachability.cli import main
from netpol_reachability.engine import Engine
from netpol_reachability.intent import load_intent, verify
from netpol_reachability.loader import load_paths

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
DEMO = EXAMPLES / "demo-cluster"


@pytest.fixture
def engine() -> Engine:
    return Engine(load_paths([str(DEMO)]))


def test_demo_cluster_loads(engine: Engine) -> None:
    assert len(engine.cluster.pods) == 4
    assert len(engine.cluster.policies) == 4
    assert engine.cluster.namespaces["monitoring"].labels["purpose"] == "observability"


def test_demo_intent_has_exactly_two_drifts(engine: Engine) -> None:
    report = verify(engine, load_intent(EXAMPLES / "intent.yaml"))
    assert report.checked == 5
    assert not report.empty_rules
    names = sorted(v.rule.name for v in report.violations)
    assert names == ["frontend can call the api", "frontend can reach the database"]
    assert not report.ok


def test_unmatched_intent_rule_is_reported(engine: Engine, tmp_path: Path) -> None:
    intent = tmp_path / "intent.yaml"
    intent.write_text(
        "rules:\n"
        "  - name: nonexistent\n"
        "    from: {namespace: prod, labels: {app: ghost}}\n"
        "    to: {namespace: prod, labels: {app: api}}\n"
        "    port: 8080\n"
        "    expect: allow\n"
    )
    report = verify(engine, load_intent(intent))
    assert [r.name for r in report.empty_rules] == ["nonexistent"]
    assert not report.ok


def test_intent_requires_a_port(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - name: x\n    expect: allow\n")
    with pytest.raises(ValueError, match="port"):
        load_intent(bad)


def test_intent_rejects_unknown_expectation(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - name: x\n    port: 80\n    expect: maybe\n")
    with pytest.raises(ValueError, match="expect"):
        load_intent(bad)


def test_cli_verify_exits_nonzero_on_drift(capsys) -> None:
    code = main(["verify", "-f", str(DEMO), "-i", str(EXAMPLES / "intent.yaml")])
    assert code == 1
    assert "DRIFT" in capsys.readouterr().out


def test_cli_verify_json_is_parseable(capsys) -> None:
    main(["verify", "-f", str(DEMO), "-i", str(EXAMPLES / "intent.yaml"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert len(payload["violations"]) == 2


def test_cli_graph_json_lists_every_ordered_pair(capsys) -> None:
    main(["graph", "-f", str(DEMO), "--port", "8080", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 12  # 4 pods, ordered pairs, no self-flows


def test_cli_graph_mermaid_emits_a_graph(capsys) -> None:
    main(["graph", "-f", str(DEMO), "--port", "8080", "--format", "mermaid"])
    out = capsys.readouterr().out
    assert out.startswith("graph LR")
    assert "-->" in out


def test_cli_explain_reports_both_directions(capsys) -> None:
    code = main(
        [
            "explain",
            "-f", str(DEMO),
            "--src", "prod/frontend-1",
            "--dst", "prod/api-1",
            "--port", "8080",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "DENIED" in out
    assert "egress" in out and "ingress" in out


def test_cli_explain_unknown_pod_is_a_usage_error(capsys) -> None:
    code = main(
        ["explain", "-f", str(DEMO), "--src", "prod/nope", "--dst", "prod/api-1", "--port", "8080"]
    )
    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_cli_requires_a_source(capsys) -> None:
    assert main(["graph"]) == 2
    assert "--file" in capsys.readouterr().err


def test_cli_parses_protocol_qualified_ports(capsys) -> None:
    main(["graph", "-f", str(DEMO), "--port", "UDP/53", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert {p["protocol"] for p in payload} == {"UDP"}


def test_stdin_source(capsys, monkeypatch) -> None:
    import io

    combined = "\n---\n".join(p.read_text() for p in sorted(DEMO.glob("*.yaml")))
    monkeypatch.setattr("sys.stdin", io.StringIO(combined))
    main(["graph", "-f", "-", "--port", "8080", "--format", "json"])
    assert len(json.loads(capsys.readouterr().out)) == 12
