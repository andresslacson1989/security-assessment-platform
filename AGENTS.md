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
