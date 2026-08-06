# netpol-reachability

**Kubernetes NetworkPolicies are written, applied, and then never verified.** This tool computes the pod-to-pod flow graph your policies *actually* produce, and diffs it against a file describing what you *meant* them to do.

No cluster required. No CNI required. Point it at YAML and get an answer in under a second.

```
$ netpol-reachability verify -f examples/demo-cluster -i examples/intent.yaml

DRIFT      frontend can call the api: prod/frontend-1 -> prod/api-1 TCP/8080 is denied but was expected to be allowed
           egress: denied — selected by prod/frontend-egress-lockdown with no matching rule
           ingress: allowed by prod/api-allow-frontend
DRIFT      frontend can reach the database: prod/frontend-1 -> prod/database-1 TCP/5432 is denied but was expected to be allowed
           egress: allowed by prod/frontend-egress-lockdown
           ingress: denied — selected by prod/database-deny-all-ingress with no matching rule

5 intent rule(s), 5 pod pair(s) evaluated, 2 drift(s), 0 unmatched.
FAILED
```

Exit code `1`. Put it in CI and the pull request fails.

---

## Why this exists

A NetworkPolicy does not describe a connection. It describes **one half** of one. A packet from A to B is delivered only if egress is permitted out of A *and* ingress is permitted into B — and each side flips independently from default-allow to default-deny the moment any policy selects that pod for that direction.

That produces three failure modes that no linter catches, because every individual manifest is valid:

1. **A correct ingress rule that never fires**, because someone later added an egress policy to the source pod for an unrelated reason.
2. **A deny that isn't a deny**, because the policy sets `policyTypes: ["Ingress"]` and the traffic you cared about was egress.
3. **A cross-namespace rule that silently matches nothing**, because a bare `podSelector` is scoped to the policy's own namespace and needs a `namespaceSelector` to escape it.

All three are in `examples/demo-cluster`, and all three are things you only discover in production, at 3am, from the application side.

## Quickstart (5 minutes, no cluster)

```bash
git clone https://github.com/OWNER/netpol-reachability
cd netpol-reachability
pip install -e .

# What can actually talk to what, on port 8080?
netpol-reachability graph -f examples/demo-cluster --port 8080

# Does reality match what the team believes?
netpol-reachability verify -f examples/demo-cluster -i examples/intent.yaml

# Why is this one flow blocked?
netpol-reachability explain -f examples/demo-cluster \
  --src prod/frontend-1 --dst prod/api-1 --port 8080
```

Prefer Docker:

```bash
docker build -t netpol-reachability .
docker run --rm netpol-reachability graph -f /examples/demo-cluster
```

The `graph` output tells you not just the verdict but which policy produced it:

```
SOURCE                   DESTINATION              PORT      VERDICT  WHY
-----------------------  -----------------------  --------  -------  ------------------------------------------------
prod/frontend-1          prod/api-1               TCP/8080  DENY     egress blocked by prod/frontend-egress-lockdown
prod/api-1               prod/frontend-1          TCP/8080  allow    egress default-allow; ingress default-allow
prod/api-1               prod/database-1          TCP/8080  DENY     ingress blocked by prod/database-deny-all-ingress
monitoring/prometheus-1  prod/api-1               TCP/8080  allow    egress default-allow; ingress prod/allow-monitoring-scrape
```

## Running against a real cluster

```bash
netpol-reachability verify --from-cluster -i intent.yaml
netpol-reachability graph --from-cluster --context staging --format mermaid
```

Or pipe manifests in from anywhere:

```bash
kubectl get pods,namespaces,networkpolicies -A -o yaml \
  | netpol-reachability graph -f - --allowed-only
```

It works equally on OpenShift; nothing here depends on upstream-only APIs.

## The intent file

```yaml
rules:
  - name: frontend can call the api
    from: {namespace: prod, labels: {app: frontend}}
    to:   {namespace: prod, labels: {app: api}}
    port: 8080
    protocol: TCP        # optional, defaults to TCP
    expect: allow        # allow | deny
```

Every rule expands to all matching source/destination pod pairs and each pair is checked. A rule matching **zero** pairs is reported as `UNMATCHED` and fails the run — a rule that silently checks nothing is worse than no rule at all.

`from` and `to` accept `namespace`, `labels`, or a full `selector` with `matchExpressions`.

## Use it in CI

```yaml
- name: verify network policy intent
  run: |
    pip install netpol-reachability
    netpol-reachability verify -f k8s/ -i network-intent.yaml
```

Because it reads plain YAML, this runs on the pull request, before anything is applied.

## What it models

| Behaviour | Supported |
|---|---|
| Ingress and egress evaluated independently | yes |
| Default-allow until a policy selects the pod | yes |
| `policyTypes` inference when the field is omitted | yes |
| Empty `ingress`/`egress` list as deny-all | yes |
| Empty `from`/`to` as allow-from-anywhere | yes |
| `podSelector` scoped to the policy namespace | yes |
| `namespaceSelector`, including `kubernetes.io/metadata.name` | yes |
| Combined `namespaceSelector` + `podSelector` in one peer | yes |
| `matchExpressions` (`In`, `NotIn`, `Exists`, `DoesNotExist`) | yes |
| Named ports resolved against the destination pod | yes |
| Port ranges via `endPort` | yes |
| Protocol matching (TCP/UDP/SCTP) | yes |

**Deliberately out of scope**, so you know exactly what you are trusting:

- `ipBlock` peers. They describe traffic outside the pod network and never authorize a pod-to-pod flow, so they are evaluated as non-matching for pod pairs.
- CNI-specific CRDs — Cilium `CiliumNetworkPolicy`, Calico `NetworkPolicy` in the `projectcalico.org` group. Only upstream `networking.k8s.io/v1` is modelled. If your cluster relies on those, this tool sees a subset of the truth and will say so by omission.
- Anything below layer 4: service mesh authorization policies, L7 rules, mTLS.
- Services, Ingress objects, and DNS. This is pod-to-pod only.

## How it compares

- `kubectl` and admission linters validate *schema*. This validates *effect*.
- `np-viewer` and similar visualizers draw the policies. This computes the flow graph and tells you where it disagrees with you.
- Connectivity testers (`kubectl-np-test`, in-cluster probe pods) measure the real dataplane, which is authoritative but needs a running cluster and a deployed workload. This runs on a laptop against a pull request, and answers *why*, not just *whether*.

The honest framing: this is a static model, and a static model can be wrong where your CNI diverges from the spec. Use it to catch the eighty percent of policy bugs that are pure logic errors, before they reach a cluster.

## Development

```bash
make install
make test      # 29 tests covering the spec semantics above
make lint
```

Each test in `tests/test_engine.py` encodes one rule from the NetworkPolicy specification, so the test file doubles as documentation of the semantics.

## Contributing

Bug reports with a minimal manifest pair (policy + expected verdict) are the most useful contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT.
