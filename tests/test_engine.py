"""Semantics tests. Each one encodes a rule from the NetworkPolicy spec."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from netpol_reachability.engine import Engine
from netpol_reachability.loader import build_cluster


def cluster_from(*parts: str):
    """Join YAML fragments, dedenting each one independently."""
    text = "\n---\n".join(textwrap.dedent(part).strip() for part in parts)
    return build_cluster([d for d in yaml.safe_load_all(text) if d])


def pod(cluster, ref):
    return next(p for p in cluster.pods if p.ref == ref)


BASE_PODS = """
apiVersion: v1
kind: Namespace
metadata: {name: prod, labels: {env: production}}
---
apiVersion: v1
kind: Namespace
metadata: {name: other, labels: {env: staging}}
---
apiVersion: v1
kind: Pod
metadata: {name: a, namespace: prod, labels: {app: a}}
spec:
  containers:
    - name: c
      ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: b, namespace: prod, labels: {app: b}}
spec:
  containers:
    - name: c
      ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: c, namespace: other, labels: {app: c}}
spec:
  containers:
    - name: c
      ports: [{name: http, containerPort: 8080}]
"""


def test_no_policies_means_everything_is_allowed():
    engine = Engine(cluster_from(BASE_PODS))
    flow = engine.flow(pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080)
    assert flow.allowed
    assert flow.egress.default_allow and flow.ingress.default_allow


def test_empty_ingress_rules_deny_all_ingress():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: lockdown, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
            """
        )
    )
    flow = engine.flow(pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080)
    assert not flow.allowed
    assert flow.egress.allowed  # egress is untouched
    assert not flow.ingress.allowed


def test_ingress_allow_is_not_enough_without_egress():
    """The core failure mode this tool exists to catch."""
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: allow-a, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{podSelector: {matchLabels: {app: a}}}]
            ---
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: a-egress, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: a}}
              policyTypes: ["Egress"]
              egress:
                - to: [{podSelector: {matchLabels: {app: zzz}}}]
            """
        )
    )
    flow = engine.flow(pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080)
    assert flow.ingress.allowed
    assert not flow.egress.allowed
    assert not flow.allowed


def test_bare_pod_selector_does_not_cross_namespaces():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: allow-c-by-label, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{podSelector: {matchLabels: {app: c}}}]
            """
        )
    )
    # Pod "c" lives in namespace `other`, so a bare podSelector must not match it.
    flow = engine.flow(pod(engine.cluster, "other/c"), pod(engine.cluster, "prod/b"), 8080)
    assert not flow.allowed


def test_namespace_selector_matches_implicit_name_label():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: allow-other-ns, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from:
                    - namespaceSelector:
                        matchLabels:
                          kubernetes.io/metadata.name: other
            """
        )
    )
    assert engine.flow(
        pod(engine.cluster, "other/c"), pod(engine.cluster, "prod/b"), 8080
    ).allowed


def test_named_port_resolves_against_destination_pod():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: named, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{podSelector: {matchLabels: {app: a}}}]
                  ports: [{protocol: TCP, port: http}]
            """
        )
    )
    a, b = pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b")
    assert engine.flow(a, b, 8080).allowed
    assert not engine.flow(a, b, 9090).allowed


def test_end_port_defines_an_inclusive_range():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: range, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{podSelector: {matchLabels: {app: a}}}]
                  ports: [{protocol: TCP, port: 8000, endPort: 8100}]
            """
        )
    )
    a, b = pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b")
    assert engine.flow(a, b, 8000).allowed
    assert engine.flow(a, b, 8100).allowed
    assert not engine.flow(a, b, 8101).allowed


def test_protocol_is_part_of_the_match():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: udp-only, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{podSelector: {matchLabels: {app: a}}}]
                  ports: [{protocol: UDP, port: 53}]
            """
        )
    )
    a, b = pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b")
    assert engine.flow(a, b, 53, "UDP").allowed
    assert not engine.flow(a, b, 53, "TCP").allowed


def test_ip_block_peer_never_authorizes_pod_to_pod():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: cidr, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from: [{ipBlock: {cidr: 0.0.0.0/0}}]
            """
        )
    )
    assert not engine.flow(
        pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080
    ).allowed


def test_match_expressions_are_supported():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: expr, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - from:
                    - podSelector:
                        matchExpressions:
                          - {key: app, operator: In, values: [a, z]}
            """
        )
    )
    assert engine.flow(
        pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080
    ).allowed


def test_policy_types_are_inferred_when_absent():
    cluster = cluster_from(
        """
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata: {name: inferred, namespace: prod}
        spec:
          podSelector: {}
          egress:
            - to: []
        """
    )
    assert cluster.policies[0].policy_types == ("Ingress", "Egress")


def test_policy_types_default_to_ingress_only():
    cluster = cluster_from(
        """
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata: {name: inferred, namespace: prod}
        spec:
          podSelector: {}
          ingress:
            - from: []
        """
    )
    assert cluster.policies[0].policy_types == ("Ingress",)


def test_empty_from_allows_any_peer():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: any, namespace: prod}
            spec:
              podSelector: {matchLabels: {app: b}}
              policyTypes: ["Ingress"]
              ingress:
                - ports: [{protocol: TCP, port: 8080}]
            """
        )
    )
    assert engine.flow(
        pod(engine.cluster, "prod/a"), pod(engine.cluster, "prod/b"), 8080
    ).allowed


def test_discover_ports_includes_container_and_policy_ports():
    engine = Engine(
        cluster_from(
            BASE_PODS,
            """
            apiVersion: networking.k8s.io/v1
            kind: NetworkPolicy
            metadata: {name: p, namespace: prod}
            spec:
              podSelector: {}
              policyTypes: ["Ingress"]
              ingress:
                - ports: [{protocol: UDP, port: 53}]
            """
        )
    )
    assert ("TCP", 8080) in engine.discover_ports()
    assert ("UDP", 53) in engine.discover_ports()


def test_unsupported_selector_operator_raises():
    from netpol_reachability.selectors import matches_selector

    with pytest.raises(ValueError):
        matches_selector(
            {"matchExpressions": [{"key": "a", "operator": "Bogus"}]}, {"a": "b"}
        )
