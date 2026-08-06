"""Load a Cluster from YAML manifests, a directory, stdin, or a live cluster.

The loader is deliberately tolerant: it ignores kinds it does not care about, so
you can point it at a whole manifest directory or the output of
`kubectl get pods,namespaces,networkpolicies -A -o yaml`.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

from .model import Cluster, Namespace, NetworkPolicy, Peer, Pod, Port, Rule

YAML_SUFFIXES = {".yaml", ".yml", ".json"}
RELEVANT_KINDS = {"pod", "namespace", "networkpolicy"}


def load_paths(paths: Iterable[str]) -> Cluster:
    docs: list[dict[str, Any]] = []
    for path in paths:
        if path == "-":
            docs.extend(_parse(sys.stdin.read()))
            continue
        p = Path(path)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.suffix.lower() in YAML_SUFFIXES and child.is_file():
                    docs.extend(_parse(child.read_text()))
        elif p.is_file():
            docs.extend(_parse(p.read_text()))
        else:
            raise FileNotFoundError(f"no such file or directory: {path}")
    return build_cluster(docs)


def load_from_kubectl(context: str | None = None) -> Cluster:
    cmd = ["kubectl", "get", "pods,namespaces,networkpolicies", "-A", "-o", "yaml"]
    if context:
        cmd.extend(["--context", context])
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return build_cluster(list(_parse(out)))


def _parse(text: str) -> Iterator[dict[str, Any]]:
    for doc in yaml.safe_load_all(text):
        if isinstance(doc, dict):
            yield from _flatten(doc)


def _flatten(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Expand List kinds (as produced by `kubectl get -o yaml`)."""
    kind = (doc.get("kind") or "").lower()
    if kind.endswith("list") and isinstance(doc.get("items"), list):
        for item in doc["items"]:
            if isinstance(item, dict):
                yield from _flatten(item)
    else:
        yield doc


def build_cluster(docs: list[dict[str, Any]]) -> Cluster:
    cluster = Cluster()
    for doc in docs:
        kind = (doc.get("kind") or "").lower()
        if kind not in RELEVANT_KINDS:
            continue
        if kind == "namespace":
            ns = _namespace(doc)
            cluster.namespaces[ns.name] = ns
        elif kind == "pod":
            cluster.pods.append(_pod(doc))
        else:
            cluster.policies.append(_policy(doc))

    for pod in cluster.pods:
        cluster.namespace(pod.namespace)
    for policy in cluster.policies:
        cluster.namespace(policy.namespace)
    return cluster


def _meta(doc: dict[str, Any]) -> dict[str, Any]:
    return doc.get("metadata") or {}


def _namespace(doc: dict[str, Any]) -> Namespace:
    meta = _meta(doc)
    return Namespace(name=meta.get("name", ""), labels=dict(meta.get("labels") or {}))


def _pod(doc: dict[str, Any]) -> Pod:
    meta = _meta(doc)
    ports: list[tuple[str, int, str]] = []
    for container in (doc.get("spec") or {}).get("containers") or []:
        for port in container.get("ports") or []:
            if "containerPort" in port:
                ports.append(
                    (
                        port.get("name") or "",
                        int(port["containerPort"]),
                        (port.get("protocol") or "TCP").upper(),
                    )
                )
    return Pod(
        name=meta.get("name", ""),
        namespace=meta.get("namespace") or "default",
        labels=dict(meta.get("labels") or {}),
        container_ports=tuple(ports),
    )


def _policy(doc: dict[str, Any]) -> NetworkPolicy:
    meta = _meta(doc)
    spec = doc.get("spec") or {}
    ingress = tuple(_rule(r, "from") for r in spec.get("ingress") or [])
    egress = tuple(_rule(r, "to") for r in spec.get("egress") or [])

    declared = spec.get("policyTypes")
    if declared:
        policy_types = tuple(str(t) for t in declared)
    else:
        # Per the API spec: Ingress is always implied; Egress only if egress
        # rules are present.
        policy_types = ("Ingress", "Egress") if egress else ("Ingress",)

    return NetworkPolicy(
        name=meta.get("name", ""),
        namespace=meta.get("namespace") or "default",
        pod_selector=dict(spec.get("podSelector") or {}),
        policy_types=policy_types,
        ingress=ingress,
        egress=egress,
    )


def _rule(raw: dict[str, Any] | None, peer_key: str) -> Rule:
    raw = raw or {}
    peers = tuple(_peer(p) for p in raw.get(peer_key) or [])
    ports = tuple(_port(p) for p in raw.get("ports") or [])
    return Rule(peers=peers, ports=ports)


def _peer(raw: dict[str, Any]) -> Peer:
    return Peer(
        pod_selector=raw.get("podSelector"),
        namespace_selector=raw.get("namespaceSelector"),
        ip_block=raw.get("ipBlock"),
    )


def _port(raw: dict[str, Any]) -> Port:
    port = raw.get("port")
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    end_port = raw.get("endPort")
    return Port(
        protocol=(raw.get("protocol") or "TCP").upper(),
        port=port,
        end_port=int(end_port) if end_port is not None else None,
    )
