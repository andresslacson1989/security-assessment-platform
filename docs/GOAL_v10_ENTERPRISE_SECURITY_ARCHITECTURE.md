# CyberAssess v10 Enterprise Security Architecture & Assurance Goal

## 0. Mission

Transform the current CyberAssess repository into an enterprise-grade security assessment and vulnerability-management platform whose **control plane, data plane, execution plane, identity system, multi-tenant authorization model, evidence chain, software supply chain, and operational behavior are all explicitly secured, testable, auditable, and contract-defined**.

The implementation MUST be based on the repository's actual current code and MUST NOT rely on assumptions about files, interfaces, or behavior that are not present in the repository.

The implementation MUST preserve valid existing functionality unless the function conflicts with an explicit requirement below.

The implementation MUST NOT add functionality merely because it is fashionable or convenient. Every architectural change MUST have a security, correctness, scalability, reliability, maintainability, or standards-alignment justification.

---

# 1. Mandatory implementation sequence

## 1.1 Contract-first rule

Before modifying implementation code:

1. Inspect the complete repository.
2. Inspect all existing contracts under `contracts/` and mirrored contract documentation under `docs/contracts/`.
3. Identify all contracts affected by this goal.
4. Update the contracts FIRST.
5. Ensure all contract terminology, schemas, endpoint behavior, state transitions, security guarantees, configuration semantics, and acceptance criteria are internally consistent.
6. Only after the contract changes are complete may implementation begin.
7. Implementation MUST be demonstrably traceable to the updated contracts.
8. Tests MUST verify contract requirements.
9. At completion, perform a contract-to-code audit and a code-to-test audit.

The agent MUST NOT implement first and "document later."

---

# 2. Standards baseline

The resulting system SHALL be designed against the following enterprise standards and practices:

## 2.1 Application security

Primary:
* OWASP ASVS 5.0.0
* OWASP Secure Code Review guidance
* OWASP SSRF Prevention guidance
* OWASP Authentication and Session Management guidance

ASVS verification identifiers MUST be recorded in project security documentation where applicable. Use version-qualified identifiers such as `v5.0.0-x.y.z` so that future ASVS changes cannot silently alter the meaning of a requirement.

## 2.2 Secure development

Use:
* NIST SP 800-218 SSDF v1.1 as the current final baseline
* SSDF v1.2 draft requirements ONLY when explicitly marked as supplementary/non-final
* NIST SP 800-53 Rev. 5 / current published 5.2.0 control concepts where applicable

The implementation MUST NOT claim regulatory certification solely because these practices have been implemented.

## 2.3 Identity and tokens

JWT implementation MUST conform to RFC 8725 principles:
* explicit accepted algorithms
* no algorithm confusion
* no algorithm fallback
* cryptographic key separation
* issuer/audience validation where used
* expiration validation
* appropriate subject handling
* secure key management

## 2.4 Supply chain

Use:
* SLSA provenance concepts
* cryptographically verified artifacts
* pinned versions
* immutable release references
* SBOM generation using a recognized standard such as CycloneDX

## 2.5 Reporting

Maintain SARIF compatibility where already implemented. Do not break SARIF 2.1.0 output compatibility unless the contract explicitly changes.

---

# 3. Enterprise architecture target

CyberAssess MUST be logically separated into:

```text
                    CONTROL PLANE
                         |
        +----------------+----------------+
        |                |                |
     Identity         Assets          Findings
        |                |                |
        +----------------+----------------+
                         |
                  Scan Scheduler
                         |
                    Message Queue
                         |
                EXECUTION PLANE
          +--------------+--------------+
          |              |              |
       DAST Worker    SAST Worker    Infra Worker
          |              |              |
       Sandbox        Sandbox         Sandbox
          +--------------+--------------+
                         |
                   Evidence Layer
                         |
               PostgreSQL / SQLite*
                         |
                 Object Storage*
```

`*` SQLite is permitted for single-node standalone deployments. PostgreSQL/object storage SHALL be the authoritative enterprise deployment architecture.

The existing FastAPI application MUST be treated as the control plane, not as the privileged security-testing execution environment.

---

# 4. Global security principles

The implementation MUST follow these principles:

## 4.1 Zero trust
No request is trusted merely because it originated inside the application.

## 4.2 Least privilege
Every user, API key, worker, process, container, filesystem path, network connection, and tool MUST receive only the privileges required.

## 4.3 Secure failure
Security failures MUST fail closed.

## 4.4 No silent security degradation
The application MUST NOT silently downgrade security controls without explicit, auditable configuration and contract-defined behavior.

## 4.5 Security controls must be authoritative
A security boundary MUST NOT exist in only one convenient route. Authorization, tenant ownership, target authorization, and sensitive operation permissions MUST also be enforced in the service/domain/data access layer.
