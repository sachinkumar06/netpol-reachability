# Contributing

## The most valuable bug report

A semantics disagreement: a manifest set, the verdict this tool gives, and the
verdict your cluster actually produces. That is the one class of bug that
matters most here, because the entire value of the tool rests on the model
being faithful to the NetworkPolicy specification.

Please include:

- the minimal NetworkPolicy plus the two pods involved
- the exact `explain` output
- what your CNI actually did, and which CNI it is

## Development

```bash
python -m venv .venv && source .venv/bin/activate
make install
make test
make lint
```

## Adding a semantics test

Every rule the engine implements has a matching test in
`tests/test_engine.py`, named after the behaviour it pins down. New behaviour
needs a test in that style before it goes in — the test file is how the
semantics are documented.

## Scope

This project models upstream `networking.k8s.io/v1` only. CNI-specific CRDs are
out of scope; a separate parser front-end that lowers Cilium or Calico policies
into this model would be welcome as its own module, but the core engine stays
upstream-only.
