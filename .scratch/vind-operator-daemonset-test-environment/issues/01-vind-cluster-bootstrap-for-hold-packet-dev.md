Status: needs-triage
Type: AFK

# Vind cluster bootstrap for hold-packet dev

## What to build

Add a repo-owned entrypoint for creating and tearing down a repeatable `vind` Kubernetes environment for hold-packet development. The slice should cover only the base environment needed for later operator and daemon testing: cluster startup, image build or load workflow, and an objective readiness check that confirms the cluster prerequisites are present.

## Acceptance criteria

- [ ] `mise run vind-up` creates a vcluster named `hold-packet-dev` using the Docker driver.
- [ ] `mise run vind-down` hard-deletes the `hold-packet-dev` cluster; is a no-op if already absent.
- [ ] `vcluster` and `kubectl` are declared in `mise.toml` `[tools]` so `mise install` provisions them.
- [ ] `vind-up` waits for the node to reach `Ready` state before exiting (smoke check).
- [ ] Image build is out of scope for this slice — deferred to issue 02.

## Blocked by

None - can start immediately