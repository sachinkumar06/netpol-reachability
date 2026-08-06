# NetworkPolicy semantics, as implemented

This is the reference the engine is built against. Each rule maps to a test in
`tests/test_engine.py`.

## Direction independence

A flow is allowed only if egress out of the source is allowed **and** ingress
into the destination is allowed. The two evaluations share no state. This is
the single most common source of surprise: adding any egress policy to a pod
converts that pod to default-deny for egress and can revoke paths that a
perfectly correct ingress policy elsewhere still permits.

## Default allow, then allowlist

For a given pod and direction:

- If no policy selects the pod for that direction, all traffic is allowed.
- If one or more policies select it, traffic is allowed only if at least one
  rule in at least one of those policies matches. Policies are additive; there
  is no deny rule and no ordering.

## policyTypes inference

When `policyTypes` is omitted, `Ingress` is always implied, and `Egress` is
added only if the spec contains egress rules. A policy with only egress rules
and no `policyTypes` therefore also makes the pod default-deny for ingress —
a frequent and expensive surprise.

## Empty lists

- `ingress: []` or a missing `ingress` key with `Ingress` in `policyTypes`
  denies all ingress.
- A rule with an empty or absent `from`/`to` allows all peers.
- A rule with an empty or absent `ports` allows all ports.

The difference between "empty list of rules" (deny everything) and "rule with
an empty peer list" (allow everything) is one indentation level in YAML.

## Peer scoping

- `podSelector` alone: matches pods with those labels **in the policy's own
  namespace**.
- `namespaceSelector` alone: matches all pods in namespaces with those labels.
- Both in the same list element: the intersection.
- Both as separate list elements: the union.

Every namespace carries an implicit `kubernetes.io/metadata.name` label equal
to its name, which the engine synthesizes even when the Namespace object was
not supplied.

## Ports

- A numeric `port` matches exactly.
- A named `port` resolves against the **destination** pod's container ports.
- `endPort` makes the range `[port, endPort]` inclusive.
- Protocol must match; it defaults to TCP.
