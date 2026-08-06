"""The reachability engine.

A packet from `src` to `dst` on (protocol, port) is delivered only if BOTH
sides agree:

  * egress is allowed out of `src`, and
  * ingress is allowed into `dst`.

For each direction the Kubernetes rule is the same: if no policy selects the pod
for that direction, everything is allowed (default-allow). As soon as one policy
selects it, only the union of the matching rules is allowed (default-deny plus
allowlist). This asymmetry is why "the policy looks right" and "traffic actually
flows" diverge so often, and it is the whole reason this tool exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Cluster, Peer, Pod, Rule
from .selectors import matches_selector


@dataclass(frozen=True)
class DirectionVerdict:
    allowed: bool
    default_allow: bool
    """True when no policy selected the pod, so traffic passes by default."""
    selecting_policies: tuple[str, ...] = ()
    allowing_policies: tuple[str, ...] = ()

    def explain(self, direction: str) -> str:
        if self.default_allow:
            return f"{direction}: allowed (no policy selects this pod)"
        if self.allowed:
            return f"{direction}: allowed by {', '.join(self.allowing_policies)}"
        return (
            f"{direction}: denied — selected by "
            f"{', '.join(self.selecting_policies)} with no matching rule"
        )


@dataclass(frozen=True)
class Flow:
    src: Pod
    dst: Pod
    protocol: str
    port: int
    egress: DirectionVerdict
    ingress: DirectionVerdict

    @property
    def allowed(self) -> bool:
        return self.egress.allowed and self.ingress.allowed

    @property
    def reasons(self) -> tuple[str, ...]:
        return (self.egress.explain("egress"), self.ingress.explain("ingress"))


@dataclass
class Engine:
    cluster: Cluster
    _cache: dict = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ API

    def flow(self, src: Pod, dst: Pod, port: int, protocol: str = "TCP") -> Flow:
        protocol = protocol.upper()
        return Flow(
            src=src,
            dst=dst,
            protocol=protocol,
            port=port,
            egress=self._verdict("egress", src, dst, port, protocol),
            ingress=self._verdict("ingress", dst, src, port, protocol),
        )

    def all_flows(self, port: int, protocol: str = "TCP") -> list[Flow]:
        pods = self.cluster.pods
        return [
            self.flow(src, dst, port, protocol)
            for src in pods
            for dst in pods
            if src is not dst
        ]

    def discover_ports(self) -> list[tuple[str, int]]:
        """Ports worth evaluating: every container port plus every policy port."""
        found: set[tuple[str, int]] = set()
        for pod in self.cluster.pods:
            for _name, port, proto in pod.container_ports:
                found.add((proto, port))
        for policy in self.cluster.policies:
            for rule in policy.ingress + policy.egress:
                for p in rule.ports:
                    if isinstance(p.port, int):
                        found.add((p.protocol, p.port))
                        if p.end_port is not None:
                            found.add((p.protocol, p.end_port))
        return sorted(found, key=lambda item: (item[0], item[1])) or [("TCP", 80)]

    # ------------------------------------------------------------- internals

    def _verdict(
        self, direction: str, subject: Pod, other: Pod, port: int, protocol: str
    ) -> DirectionVerdict:
        selecting = [
            policy
            for policy in self.cluster.policies_in(subject.namespace)
            if policy.affects(direction)
            and matches_selector(policy.pod_selector, subject.labels)
        ]

        if not selecting:
            return DirectionVerdict(allowed=True, default_allow=True)

        allowing = []
        for policy in selecting:
            rules = policy.ingress if direction == "ingress" else policy.egress
            for rule in rules:
                if self._rule_matches(rule, policy.namespace, other, port, protocol):
                    allowing.append(policy.ref)
                    break

        return DirectionVerdict(
            allowed=bool(allowing),
            default_allow=False,
            selecting_policies=tuple(p.ref for p in selecting),
            allowing_policies=tuple(allowing),
        )

    def _rule_matches(
        self, rule: Rule, policy_ns: str, other: Pod, port: int, protocol: str
    ) -> bool:
        if not self._ports_match(rule, other, port, protocol):
            return False
        if not rule.peers:
            return True  # empty from/to means "any peer"
        return any(self._peer_matches(peer, policy_ns, other) for peer in rule.peers)

    def _ports_match(self, rule: Rule, other: Pod, port: int, protocol: str) -> bool:
        if not rule.ports:
            return True
        return any(p.matches(protocol, port, other) for p in rule.ports)

    def _peer_matches(self, peer: Peer, policy_ns: str, other: Pod) -> bool:
        if peer.is_ip_block:
            # ipBlock peers describe traffic outside the pod network, so they
            # never authorize a pod-to-pod flow. Reported separately by
            # `external_exposure`.
            return False

        ns_labels = self.cluster.namespace(other.namespace).effective_labels

        if peer.namespace_selector is None and peer.pod_selector is None:
            return False
        if peer.namespace_selector is None:
            # A bare podSelector is scoped to the policy's own namespace.
            if other.namespace != policy_ns:
                return False
            return matches_selector(peer.pod_selector, other.labels)
        if not matches_selector(peer.namespace_selector, ns_labels):
            return False
        if peer.pod_selector is None:
            return True
        return matches_selector(peer.pod_selector, other.labels)
