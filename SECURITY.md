# Security Policy

## Supported Versions

CyberAssess actively maintains and provides security updates for the following releases:

| Version | Supported          | Security Invariants |
| ------- | ------------------ | ------------------- |
| 14.x    | :white_check_mark: | Full Closure (E13)  |
| < 14.0  | :x:                | End of Life (EOL)   |

---

## Reporting a Vulnerability

The CyberAssess project takes security vulnerabilities seriously. We appreciate the responsible disclosure of security issues by researchers, partners, and the community.

### Disclosure Protocol
**DO NOT file public GitHub issues for security vulnerabilities.**

To report a vulnerability:
1. Submit a private report via **GitHub Security Advisories** on the repository:
   `https://github.com/andresslacson1989/security-assessment-platform/security/advisories/new`
   - OR -
2. Email the maintainer directly at: `andresslacson@gmail.com` with the subject prefix `[SECURITY VULNERABILITY]`.

### Information to Include
Please provide:
- A detailed description of the vulnerability and its potential impact.
- Exact reproduction steps, proof-of-concept (PoC) code, or HTTP request/response transcripts.
- Affected components, tool adapters, engines, or API endpoints.
- Any suggested remediation or patches.

### Response SLA
- **Initial Acknowledgement**: Within **48 hours** of report receipt.
- **Triage & Reproduction**: Within **7 business days**.
- **Remediation & Patch Release**: Within **30 calendar days** for Critical/High issues.
- **Coordinated Public Disclosure**: Mutually agreed date following patch deployment.

---

## Security Architecture & Invariants

CyberAssess implements formal architectural security invariants defined across:
- [`docs/SECURITY_INVARIANT_TRACEABILITY.md`](docs/SECURITY_INVARIANT_TRACEABILITY.md): Full mapping from contract requirements to concrete implementations and adversarial regression tests.
- [`contracts/`](contracts/): Formal technical contracts (01 through 09) defining isolation boundaries, RBAC, SSRF protection, process supervisor governance, and tool supply-chain controls.

Key invariants enforced at all times:
- Zero-trust authentication with RFC 8725 JWTs bound strictly to `HS256`.
- Wildcard `["*"]` authorization restricted exclusively to `PrincipalType.SYSTEM_PRINCIPAL` with `UserRole.ADMIN`.
- 8-state network classification: loopback and cloud metadata (`169.254.169.254`) are unconditionally blocked for all callers.
- Execution-scoped process supervision: scan cancellation terminates only the targeted process tree.
- Truthful evidence reporting: no synthetic `SAFE` claims on unexecuted, missing, or failed tools.
