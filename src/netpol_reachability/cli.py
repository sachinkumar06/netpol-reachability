"""Command line interface.

    netpol-reachability graph   -f examples/demo-cluster
    netpol-reachability verify  -f examples/demo-cluster -i examples/intent.yaml
    netpol-reachability explain -f examples/demo-cluster \
        --src prod/frontend-1 --dst prod/database-1 --port 5432
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import render
from .engine import Engine
from .intent import load_intent
from .intent import verify as verify_intent
from .loader import load_from_kubectl, load_paths
from .model import Cluster, Pod

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netpol-reachability",
        description="Compute the flow graph NetworkPolicies actually produce, "
        "and diff it against declared intent.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_source(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "-f",
            "--file",
            action="append",
            default=[],
            metavar="PATH",
            help="manifest file, directory, or '-' for stdin (repeatable)",
        )
        p.add_argument(
            "--from-cluster",
            action="store_true",
            help="read live objects via kubectl instead of files",
        )
        p.add_argument("--context", help="kubectl context to use with --from-cluster")

    graph = sub.add_parser("graph", help="print the allowed pod-to-pod flow graph")
    add_source(graph)
    graph.add_argument(
        "--port",
        action="append",
        default=[],
        help="port to evaluate, e.g. 8080 or UDP/53 (default: discovered ports)",
    )
    graph.add_argument(
        "--format", choices=["table", "json", "mermaid"], default="table"
    )
    graph.add_argument(
        "--allowed-only", action="store_true", help="hide denied flows"
    )

    verify = sub.add_parser("verify", help="check policies against an intent file")
    add_source(verify)
    verify.add_argument("-i", "--intent", required=True, help="path to intent YAML")
    verify.add_argument("--format", choices=["text", "json"], default="text")

    explain = sub.add_parser("explain", help="explain one specific flow")
    add_source(explain)
    explain.add_argument("--src", required=True, help="source pod as namespace/name")
    explain.add_argument("--dst", required=True, help="destination pod as namespace/name")
    explain.add_argument("--port", required=True, help="port, e.g. 5432 or UDP/53")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cluster = _load(args)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user verbatim
        print(f"error loading manifests: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not cluster.pods:
        print(
            "error: no Pod objects found. This tool needs pods (or their labels) "
            "to resolve selectors.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    engine = Engine(cluster)

    if args.command == "graph":
        return _cmd_graph(engine, args)
    if args.command == "verify":
        return _cmd_verify(engine, args)
    return _cmd_explain(engine, args)


def _load(args: argparse.Namespace) -> Cluster:
    if getattr(args, "from_cluster", False):
        return load_from_kubectl(getattr(args, "context", None))
    if not args.file:
        raise ValueError("supply -f/--file at least once, or use --from-cluster")
    return load_paths(args.file)


def _parse_port(value: str) -> tuple[str, int]:
    if "/" in value:
        proto, _, port = value.partition("/")
        return proto.upper(), int(port)
    return "TCP", int(value)


def _find_pod(cluster: Cluster, ref: str) -> Pod:
    for pod in cluster.pods:
        if pod.ref == ref or pod.name == ref:
            return pod
    known = ", ".join(sorted(p.ref for p in cluster.pods))
    raise KeyError(f"pod {ref!r} not found. Known pods: {known}")


def _cmd_graph(engine: Engine, args: argparse.Namespace) -> int:
    targets = (
        [_parse_port(p) for p in args.port] if args.port else engine.discover_ports()
    )
    flows = []
    for protocol, port in targets:
        flows.extend(engine.all_flows(port, protocol))

    if args.format == "json":
        print(render.flows_json(flows))
    elif args.format == "mermaid":
        print(render.flows_mermaid(flows))
    else:
        print(render.flows_table(flows, show_denied=not args.allowed_only))
    return EXIT_OK


def _cmd_verify(engine: Engine, args: argparse.Namespace) -> int:
    try:
        rules = load_intent(args.intent)
    except Exception as exc:  # noqa: BLE001
        print(f"error loading intent: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = verify_intent(engine, rules)
    print(render.drift_json(report) if args.format == "json" else render.drift_text(report))
    return EXIT_OK if report.ok else EXIT_DRIFT


def _cmd_explain(engine: Engine, args: argparse.Namespace) -> int:
    try:
        src = _find_pod(engine.cluster, args.src)
        dst = _find_pod(engine.cluster, args.dst)
        protocol, port = _parse_port(args.port)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    flow = engine.flow(src, dst, port, protocol)
    verdict = "ALLOWED" if flow.allowed else "DENIED"
    print(f"{src.ref} -> {dst.ref} {protocol}/{port}: {verdict}")
    for reason in flow.reasons:
        print(f"  {reason}")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
