# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.2.x (`main`) | Yes |
| 0.1.x | No (v0 record format, removed; see CHANGELOG.md) |

There are no releases yet. Fixes land on `main`.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:
<https://github.com/CMABERY/4GARTHA/security/advisories/new>. Please do not open a public pull request
or discussion for an unfixed vulnerability. Include the commit, a minimal reproduction, and which
assurance in [ASSURANCE.md](ASSURANCE.md) it breaks.

This is a small project maintained on a best-effort basis. No response time is promised.

## What counts as a vulnerability

A report is in scope when the implementation does something [ASSURANCE.md](ASSURANCE.md) says it
must not. For example:

- the verifier reports PASS (or a profile as satisfied) for an assurance the evidence does not
  support, or reports PASS for any of the four assurances v1 says can never PASS
- two different claims share a record ID, or a record's bytes can change without changing its ID,
  through an implementation defect (a demonstrated SHA-256 collision or preimage would break the
  stated assumption rather than this implementation; please report that too)
- a record can make the verifier execute anything other than its policy-defined runtime, or a
  transform executes when replay was not requested or integrity did not pass
- a workflow invokes ledger derivation replay, or a CI job obtains write permissions
- `ledger` commands write outside `ledger/` (for example through ref names) or overwrite stored
  objects or records

## Known limitations (documented, not vulnerabilities)

- **Replay is not sandboxed.** `ledger replay` and `ledger verify --replay` run transform code as
  your user, with your filesystem and network access. Do not replay records whose transforms you
  would not run yourself. The verifier reports `execution_safety: FAIL` whenever it does this
  (ASSURANCE.md 5.4).
- **No authenticity or governance assurance.** Admissions are unattested statements, and repository
  history is protected only by repository settings that are not yet enforced (ASSURANCE.md 5.6, 5.7).
- CI does not invoke ledger derivation replay, but it is not a sandbox. Pull-request workflows run
  the PR's own code (package build, tests, tools) with a read-only token, subject to GitHub Actions'
  permissions and contributor approval policy. This is inherent to running CI on pull requests.
