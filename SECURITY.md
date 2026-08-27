# Security policy

Andon's product is a verdict about whether a change can be trusted, and
`docs/trust-boundary.md` publishes exactly where that verdict holds and where it
does not. A way to make Andon say `pass` or `confirmed` about a change it should
have stopped is therefore a security issue for this tool in a way it would not
be for a linter: every repository running Andon as a gate inherits the hole, and
the gate keeps reporting green while it is open.

## What to report privately

Report privately, before anywhere else, anything that lets a change get past
the tool without the tool noticing:

- **A detector evasion.** A change that does what one of the seven tamper
  detectors exists to catch — withdraws test evidence, hides code from analysis,
  loosens a quality gate, replaces an implementation with its expected answers —
  and does not fire it. `fixtures/adversarial/README.md` already enumerates the
  evasions the suite is known to miss; a new one is one not on that list.
- **An attestation the verifier did not earn.** A way to obtain `confirmed` or
  `confirmed-static` without CI recomputing the change, to get a forged
  self-report through the digest compare, or to make a tamper signal disappear
  from the verifier's outcome.
- **A sandbox escape** beyond what `docs/sandbox.md` says the sandbox isolates.
- **Supply chain.** A pinned action, checksum, or dependency in
  `.github/workflows/` or `deny.toml` that does not pin what it claims to.

Why the private route matters here specifically: the public corpus under
`fixtures/adversarial/` is a published list of what the detectors catch, and its
complement is the evasion manual. A public issue describing a new evasion is a
working exploit against every gate running Andon, published before the fix
exists. A private report becomes a fix that lands together with its public
fixture, and only then is the evasion public — as a case the suite catches.

## How to report

Use GitHub's private vulnerability reporting: the **Report a vulnerability**
button under the repository's **Security** tab, or directly at
<https://github.com/gtm-k/andon/security/advisories/new>. The report is visible
to the maintainer and to you, and to nobody else until it is published.

Private vulnerability reporting is a repository setting, and enabling it is
part of the checklist for making this repository public. If the button is
missing, that step was missed: open an ordinary issue containing only the words
"security report — private reporting is not enabled" and nothing about the
finding, and a channel will be arranged from there.

Do not put the details in an issue, a pull request, a discussion, or a commit.

## What a report should contain

- The Andon version (`andon --version`), or the commit you built from.
- Which detector, attestation value, or boundary is affected.
- The smallest change that demonstrates it, ideally in the corpus's own shape —
  a `base/` tree, a `head/` tree, and what you expected to fire — so the fix
  can ship with its fixture.
- What Andon actually said: the output of `andon measure --json` on that
  change, and the verdict you believe it should have reached.
- Whether you know of the evasion being used anywhere.

## What happens next

One maintainer runs this project today, so the numbers below are what one
person can hold to rather than what a team would promise.

- **Acknowledgement within 7 days** of the report.
- **Triage within 14 days**: whether it reproduces, whether it is a new evasion
  or one already listed as known, and how severe it is judged to be.
- **A fix timeline stated at triage**, not before. Detector fixes are bound by
  the project's corpus rule (`CONTRIBUTING.md`): the fix lands with a public
  case in `fixtures/adversarial/` demonstrating the evasion, the corpus is
  re-frozen and re-measured, and the case may additionally be kept in the
  private held-back set as a regression specimen.
- **Disclosure** when the fix is released, or 90 days after triage, whichever
  comes first. If you need a different window, say so in the report.
- **Credit**, if you want it, in the fixture's `case.toml` note and in the
  advisory.

## What is not a security report

These are already disclosed, and are design limits rather than bugs — a report
about one of them will be answered with a pointer, not a fix:

- **The version-skew laundering window.** A self-report stamping an engine
  version the verifier is not running is demoted to
  `unwitnessed-version-skew`, which does not count downstream. Disclosed in
  `docs/trust-boundary.md`; closed by the hermetic version-matched recompute.
- **Hand-written attestations.** Anyone with push access can write
  `refs/notes/andon-attest`; v1 attestation trust is GitHub Actions provenance,
  not cryptography. Disclosed in `docs/trust-boundary.md`; Sigstore signing is
  the named hardening.
- **The sandbox is not a security boundary against a hostile repository.**
  `docs/sandbox.md` says what it does isolate.
- **Unsupported languages return `pass`** because nothing measured them, and
  Andon ships no SAST family. The language table in `README.md` is the scope.
- **Evasions already listed** under "Evasions the suite does not catch" in
  `fixtures/adversarial/README.md`. A pull request closing one of them is
  welcome, under the corpus rule.

A detector that fired when it should **not** have is a false positive, not a
security issue: open an issue with the false-positive template.

## Supported versions

Andon is pre-1.0. Reports are assessed against the latest commit on `main`, and
a fix ships in the next release rather than as a patch to an earlier one.
