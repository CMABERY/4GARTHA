# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.3.x (`main`) | Yes |
| 0.2.x | No (assurance contract 1; see CHANGELOG.md) |
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
  support, reports PASS for execution safety, reproducibility or authenticity, or reports
  governance PASS without the verifier's own anchor policy
- governance PASS when the anchor files, checkpoint signature, Sigsum proof or witness quorum do not
  support it; a time bound earlier than the cosignatures justify; a policy read from anywhere other
  than the file the verifier named; or contradictory anchoring evidence reported as anything but
  FAIL
- two different claims share a record ID, or a record's bytes can change without changing its ID,
  through an implementation defect (a demonstrated SHA-256 collision or preimage would break the
  stated assumption rather than this implementation; please report that too)
- a record can make the verifier execute anything other than its policy-defined runtime, or a
  transform executes when replay was not requested or integrity did not pass
- the CI admission gate replays a submitted record, or a CI job obtains write permissions
- `ledger` commands write outside `ledger/` (for example through ref names) or overwrite stored
  objects or records

## Known limitations (documented, not vulnerabilities)

- **Replay is not sandboxed.** `ledger replay` and `ledger verify --replay` run transform code as
  your user, with your filesystem and network access. Do not replay records whose transforms you
  would not run yourself. The verifier reports `execution_safety: FAIL` whenever it does this
  (ASSURANCE.md 5.4).
- **No authenticity assurance.** Admissions are unattested statements (ASSURANCE.md 5.6).
- **Governance is narrow.** A governance PASS shows that a record's lineage was in an externally
  logged checkpoint by a time bound. It does not show that no later or conflicting checkpoint
  exists: whoever holds the anchor key can publish a rebuilt history. Seeing that needs a monitor,
  which does not exist yet (ASSURANCE.md 5.7). Nothing has been anchored in production yet, and
  repository history is otherwise protected only by a branch ruleset that the repository's admins
  can change.
- **Sigsum's tools are more lenient than this verifier** in a few documented cases (for example,
  one invalid witness cosignature when the quorum is met anyway). This verifier reports FAIL for
  those, by design (`conformance/anchor-v1-vectors.json`).
- CI does not replay newly submitted ledger records as part of its admission gate. The test suite deliberately executes fixture transforms to test replay behavior. Pull-request builds, tests, and tools still execute contributor-controlled code and are not sandboxed. PR workflows run with a read-only token, subject to GitHub Actions' permissions and
  contributor approval policy. This is inherent to running CI on pull requests.
