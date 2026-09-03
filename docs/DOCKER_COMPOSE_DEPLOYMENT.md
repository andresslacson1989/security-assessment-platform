# Docker Compose deployment boundary

This deployment profile keeps CyberAssess on Docker Compose while preserving the
contract boundary between the control plane, persistence services, and the
enterprise execution worker.

## Network separation

- `control-plane` is used by the HTTP service.
- `data-plane` is `internal: true` and carries only PostgreSQL, Redis, and the
  enterprise control-plane/worker connections.
- `execution-egress` is attached only to the enterprise worker. It is the
  attachment point for the host firewall or an egress gateway.
- `provider-egress` is attached to the enterprise control plane for
  platform-owned provider clients. Application-layer URL allowlists still
  apply.

PostgreSQL and Redis have no published host ports. The worker has no published
host port and cannot receive inbound traffic through the Compose file.

## Required production control

Docker Compose network declarations do not provide a dynamic, per-tenant
destination allowlist. A production deployment MUST place an independently
managed egress control on the `execution-egress` attachment before enabling
assured external-tool execution. That control must:

1. default-deny external traffic from the worker;
2. allow DNS only to the approved resolver;
3. allow platform-owned provider destinations only when the provider policy
   permits them; and
4. allow assessment destinations only from the authoritative, tenant-scoped
   validated-target policy.

The application must not treat `-s crtsh`, proxy variables, or any other tool
flag as a replacement for this control. If the infrastructure policy is absent
or cannot prove the worker identity and destination decision, assured external
execution must remain disabled and the scan must report degraded coverage.

This repository verifies the Compose topology and application boundaries. It
does not claim host-firewall or egress-gateway enforcement merely because the
Compose file parses successfully.

## Startup checklist

For enterprise deployment, verify the following outside the application:

- the worker container identity is bound to the egress policy;
- the default-deny policy is active before the worker starts;
- the policy audit trail records tenant, asset, destination, decision, and time;
- policy removal or controller failure blocks assured external execution; and
- a runtime probe proves an approved destination succeeds and an unapproved
  destination fails from the actual worker container.
