# Repository Delivery Policy

## GitHub-before-GitLab promotion

GitHub is the required first publication and review system for every repository
section. Before any commit or section may be published to the GitLab project,
the responsible agent MUST:

1. complete the section's implementation and verification criteria;
2. create the grouped section commit on the approved branch;
3. push that exact commit to the configured GitHub remote;
4. verify that GitHub contains the expected commit and that the local branch
   matches the intended GitHub ref; and
5. only then publish the same verified commit object to GitLab.

The GitLab push MUST identify the exact GitHub-verified commit SHA. A GitHub
failure, unverified result, dirty worktree, unresolved review blocker, or
commit mismatch MUST prevent GitLab publication. GitLab MUST NOT be used as a
substitute for the GitHub-first review and evidence step.

## GitHub-to-GitLab mirror consistency

GitHub is the canonical repository publication for this project. Every
governed repository branch, tag, commit, and file state that is published to
GitHub MUST be mirrored to the corresponding GitLab project. The mirror MUST
use the same commit objects, ref names, file contents, and reachable history;
GitLab MUST NOT become a divergent source of repository content or history.
Provider-internal refs that are not repository delivery refs, such as hosting
service pull-request metadata refs, are outside this mirror requirement.

After each approved GitHub publication, the responsible agent MUST verify that
the corresponding GitLab ref resolves to the identical GitHub-verified commit
SHA. A missing GitLab ref, divergent SHA, divergent tree, or incomplete
reachable history MUST be reported as a delivery failure and MUST NOT be
described as synchronized. Mirroring MUST use normal non-destructive ref
updates; force-pushes, history replacement, and silent conflict resolution are
not permitted. Any required GitLab-specific setup, ref repair, or mirror
verification MUST be requested from the designated GitLab agent, while the
GitHub-first review and acceptance gate remains in force.

This policy does not authorize creation of commits, pushes, remote changes, or
GitLab project changes by itself. Such actions still require explicit scope
and appropriate credentials. Runtime database files, including
`data/cyberassess.db`, MUST remain outside delivery operations: do not stage,
commit, mirror, archive, or publish them. This is not a blanket read
prohibition. A task may authorize inspection or maintenance of an exact path
and operation; use read-only access where practical, record the authorization
and evidence, and require separate explicit authorization for destructive
changes.

## Project-Disk-Only File Storage

All files created, written, extracted, generated, copied, or retained for
repository work MUST be stored on the project's disk under the repository root
(`E:\web apps\security-assessment-platform` in the current workspace), or
under an explicitly approved subdirectory of that root. Agents MUST NOT use
another local disk, an operating-system temporary directory, a user-profile
temporary directory, a desktop/downloads directory, `/tmp`, or an external
workspace to save working files, test outputs, logs, evidence, bundles,
temporary databases, validation checkouts, or generated artifacts.

The default local temporary root is
`E:\web apps\security-assessment-platform\.project-temp\`. Each run MUST use
its own clearly named subdirectory beneath that root. This directory is for
project-local temporary output only and MUST NOT be staged, committed, or
published unless a separate scope explicitly requires a specific artifact.

Before running a command or test that writes to a default temporary location,
redirect its temporary and output paths to a project-local directory and record
that location in the evidence. This storage rule does not authorize changes to
`data/cyberassess.db`, remote runtime databases, or any other protected path;
those paths remain governed by the database and delivery policies above.
Existing files and artifacts MUST NOT be deleted or relocated to enforce this
rule without separate explicit authorization.

## Section B Acceptance-Tier Amendment (2026-09-14)

This dated amendment changes delivery classification only. It does not change
application behavior, security controls, API contracts, migration invariants,
tool trust rules, database protection, or the GitHub-before-GitLab publication
rule for final repository release.

For the current delivery cycle, Section B security acceptance is a narrower
gate and may be accepted only when all of the following are independently
verified:

- execution authority, cancellation/recovery, quarantine, database, and real
  PostgreSQL Section B security vectors pass;
- real PostgreSQL executes with zero dependency-gated or unauthorized skips;
- migration provenance, one-byte source and artifact mutation rejection,
  historical/current identity separation, v13 independence, 26-tool and
  registry preservation pass;
- compilation/static checks and fresh disposable SQLite startup pass;
- no security control is weakened;
- `data/cyberassess.db` is unmodified and unstaged;
- unrelated user changes, `.ci`, `.project-temp`, `v/`, and mirror staging are
  not staged, deleted, or relocated; and
- all remaining non-security gates are explicitly recorded as open, failed,
  skipped, or unverified.

The following are overall final-release gates rather than prerequisites for
the narrower Section B security acceptance, provided that no Section B
security failure is present:

- full repository verification;
- GitHub artifact upload/finalization when the underlying security test output
  is captured and independently verifiable from the run;
- Windows and image jobs outside the Section B security boundary; and
- exact GitLab mirroring and final release publication.

These remain mandatory for declaring the entire repository delivery complete.
They must not be reported as passed merely because Section B security
acceptance passes. GitHub remains the authoritative CI/CD provider, GitLab
remains a repository mirror only, and no final GitLab promotion occurs until
the existing GitHub-first and exact-SHA rules pass.

Any later reference to final acceptance or complete repository delivery means
the overall release gate. A reference to Section B acceptance means only the
narrower security gate defined by this amendment.

## Authoritative Delivery and Contract-Acceptance Goal

The complete delivery and contract-acceptance goal is preserved verbatim in
`docs/REPOSITORY_DELIVERY_AND_CONTRACT_ACCEPTANCE_GOAL.md`. That file is the
authoritative reference for the current delivery cycle and supplements this
`AGENTS.md`.

Before evaluating, responding to, or issuing a next goal based on any
developer-agent report, the coordinating agent MUST re-read that goal file in
full. The coordinating agent MUST use it as the acceptance baseline and MUST
NOT rely on memory, summaries, or prior reports. A newer explicit user
instruction controls if it conflicts with the saved goal; the conflict and
resulting scope change MUST be recorded.
