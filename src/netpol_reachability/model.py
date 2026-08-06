"""Data model for cluster objects and NetworkPolicies.

Everything here is a plain dataclass built from parsed YAML. The engine never
touches raw dicts, which keeps the Kubernetes semantics in one place.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

Selector = dict[str, Any] | None


@dataclass(frozen=True)
class Namespace:
    name: str
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def effective_labels(self) -> dict[str, str]:
        # Kubernetes injects this label on every namespace since v1.21.
        out = dict(self.labels)
        out.setdefault("kubernetes.io/metadata.name", self.name)
        return out


@dataclass(frozen=True)
class Pod:
    name: str
    namespace: str
    labels: dict[str, str] = field(default_factory=dict)
    container_ports: tuple[tuple[str, int, str], ...] = ()
    """Tuple of (name, port, protocol); name may be empty."""

    @property
    def ref(self) -> str:
        return f"{self.namespace}/{self.name}"

    def resolve_port_name(self, name: str) -> int | None:
        for pname, port, _proto in self.container_ports:
            if pname == name:
                return port
        return None


@dataclass(frozen=True)
class Port:
    """A port constraint inside a NetworkPolicy rule."""

    protocol: str = "TCP"
    port: int | str | None = None  # None means "all ports"
    end_port: int | None = None

    def matches(self, protocol: str, port: int, target: Pod) -> bool:
        if self.protocol.upper() != protocol.upper():
            return False
        if self.port is None:
            return True
        if isinstance(self.port, str):
            resolved = target.resolve_port_name(self.port)
            if resolved is None:
                return False
            return resolved == port
        if self.end_port is not None:
            return self.port <= port <= self.end_port
        return self.port == port


@dataclass(frozen=True)
class Peer:
    """One entry in an ingress `from` or egress `to` list."""

    pod_selector: Selector = None
    namespace_selector: Selector = None
    ip_block: dict[str, Any] | None = None

    @property
    def is_ip_block(self) -> bool:
        return self.ip_block is not None


@dataclass(frozen=True)
class Rule:
    peers: tuple[Peer, ...] = ()
    """Empty tuple means "all peers" (an empty `from`/`to` allows everything)."""
    ports: tuple[Port, ...] = ()
    """Empty tuple means "all ports"."""


@dataclass(frozen=True)
class NetworkPolicy:
    name: str
    namespace: str
    pod_selector: dict[str, Any] = field(default_factory=dict)
    policy_types: tuple[str, ...] = ("Ingress",)
    ingress: tuple[Rule, ...] = ()
    egress: tuple[Rule, ...] = ()

    @property
    def ref(self) -> str:
        return f"{self.namespace}/{self.name}"

    def affects(self, direction: str) -> bool:
        return direction.lower() in {t.lower() for t in self.policy_types}


@dataclass
class Cluster:
    namespaces: dict[str, Namespace] = field(default_factory=dict)
    pods: list[Pod] = field(default_factory=list)
    policies: list[NetworkPolicy] = field(default_factory=list)

    def namespace(self, name: str) -> Namespace:
        ns = self.namespaces.get(name)
        if ns is None:
            # Namespace object was not supplied; synthesize one so that
            # namespaceSelectors still match on the implicit name label.
            ns = Namespace(name=name)
            self.namespaces[name] = ns
        return ns

    def pods_in(self, namespace: str) -> Iterator[Pod]:
        return (p for p in self.pods if p.namespace == namespace)

    def policies_in(self, namespace: str) -> Iterator[NetworkPolicy]:
        return (p for p in self.policies if p.namespace == namespace)
