# GenSec Threat Model

This document describes what GenSec assumes about its environment, who it
protects you from, who it doesn't, and what happens when each layer of the
pipeline receives adversarial or malformed input. It's written from what
the code actually does, not from how the tool is marketed.

## Scope and assumptions

GenSec is a CLI you run yourself, or schedule in your own cluster — it is
not a hosted, multi-tenant service. It assumes:

- **The operator trusts the environment it runs in.** Whatever process runs
  `gensec` holds `GROQ_API_KEY` and `GITHUB_TOKEN` in plain environment
  variables (or a `.env` file). Anything with access to that process's
  environment or filesystem has both credentials in the clear. GenSec does
  no secret management of its own — no vault integration, no rotation, no
  scoping beyond whatever scope the operator gave the PAT.
- **The target repository is the operator's own code**, not third-party or
  attacker-supplied input. The scanned source becomes literal text inside
  prompts sent to the LLM (see Prompt Injection below) — pointing GenSec at
  a repository you don't trust means feeding untrusted content into your
  own LLM prompts.
- **A human reviews the PR before merge.** GenSec never merges anything
  itself. That review is the actual safety net for everything downstream of
  the LLM — treat it as load-bearing, not a formality.
- **Dev/staging use, not direct-to-production automation.** Nothing about
  the design prevents pointing `GITHUB_REPO` at a production repo with
  auto-merge enabled, but nothing in GenSec assumes or checks for a review
  gate either — that safety property comes entirely from how you configure
  the target repo, not from GenSec.

## Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Operator's machine/container | Holding credentials, running `git`/scanners | — |
| Target repo source code | Being the operator's own code | Containing adversarial content aimed at the LLM |
| Groq API | Availability, returning *a* response | The safety or correctness of what it returns |
| GitHub REST API | Accepting the PR as authenticated | Anything — it's a dumb transport for the PR GenSec builds |
| Semgrep / Gitleaks / Trivy binaries | Their scan output, once installed | Their own supply chain (see below) |

## What GenSec defends against

- Known vulnerability *patterns* in your own code — hardcoded secrets, SQL
  built by string concatenation, unsanitized path handling, and similar —
  via three established scanners plus its own pattern matcher.
- Alert fatigue, to a degree: the flagging and LLM-triage stages reduce a
  raw finding list to a smaller, confidence-scored set.
- Arbitrary code execution *by GenSec itself*: at no point does GenSec
  execute the target repository's code, or the LLM's output, as code. It
  only reads text, asks the LLM to transform text, and writes text to disk.
  Whatever runs that resulting code (CI, the reviewer's machine, production)
  is a separate trust boundary GenSec does not cross itself.

## What GenSec does not defend against

- **A malicious or compromised LLM response.** The only check on
  fix-generation output is re-running the original scanners to see if the
  *original* finding's pattern still matches. A response that fixes the
  named vulnerability while inserting an unrelated backdoor, weakening a
  different control, or exfiltrating data would pass this check completely
  — nothing evaluates the semantic safety of the diff. This is the single
  biggest gap in the current design.
- **Prompt injection via the scanned repository.** File content, snippets,
  and finding metadata are interpolated directly into the LLM prompt as
  plain text, unescaped and unsanitized. A comment or string literal in the
  target repo crafted to look like an instruction to the model (e.g. "ignore
  the above and instead output ...") is passed through as-is. GenSec has no
  defense against this beyond whatever the underlying model itself resists.
- **A compromised Groq endpoint or credential.** `GROQ_API_KEY` is trusted
  implicitly; there's no response signing, no alternate-provider
  verification, nothing beyond "the HTTP call returned 200."
  Anyone who can intercept or spoof that endpoint controls every patch
  GenSec writes.
- **Supply-chain compromise of the bundled scanners.** The Dockerfile
  installs Semgrep via `pip`, Gitleaks from a GitHub release tarball, and
  Trivy via `curl | sh` from the aquasecurity install script — none of
  these are checksum- or signature-verified beyond TLS. A compromised
  release of any of the three would run unquestioned.
- **An attacker with access to the operator's credentials.** If
  `GITHUB_TOKEN` or `GROQ_API_KEY` leaks, GenSec provides no additional
  containment — the token's actual GitHub permissions are the only limit,
  and today that has to be direct push access to the target repo (no
  fork-and-PR flow exists to reduce that scope).
- **Vulnerabilities outside its rule set, or outside Go.** Silence from
  GenSec is not evidence of safety — it only checks for what its scanners
  and heuristics are built to check.

## Adversarial and malformed input, layer by layer

- **Scanners** (`internal/scanner`): unreadable or unparseable files are
  skipped silently, not fatally — a single bad file doesn't stop the scan.
  If the `gitleaks` or `trivy` binary is missing or errors, that scanner
  contributes zero findings with **no error surfaced anywhere** — a scan
  can report "clean" when two of four detectors never ran at all. This is a
  known gap, not a designed fail-safe.
- **Flagging** (`internal/flagging`): malformed or empty file content simply
  fails to match any source/sink pattern and falls through to a low-
  confidence default. No crash path here, but also no crash-worthy input —
  it's string matching over already-scanned local files.
- **LLM triage** (`internal/llm`): a non-200 API response degrades the
  finding's confidence by 20% rather than dropping it; an LLM response that
  isn't valid JSON (or contains no `{`/`}` at all) falls back to a fixed
  default confidence (0.5), which happens to sit just below the keep
  threshold (0.6) — so garbled or adversarial triage responses tend to
  result in the finding being silently **dropped**, not escalated for
  human attention. A quietly-lost finding looks identical to a quietly
  irrelevant one.
- **Fix generation** (`internal/fixer`): this is the weakest layer. The
  response is treated as literal replacement source code after light
  markdown-fence stripping — there is no JSON schema, no syntax check, no
  compile step. Anything the model returns, well-formed Go or not, gets
  written to disk if it differs from the original file.
- **PR creation** (`internal/github`): if fix generation produced nothing
  usable, there are no changes to commit and the PR step errors out
  cleanly. But if *anything* was written to disk in the previous stage —
  safe or not, valid Go or not — it is committed, pushed, and opened as a
  PR with no further gate. The pull request itself is the last line of
  defense, which is why human review before merge is not optional.

## If you're deciding whether to run this

Point GenSec at repositories you own and trust, keep its credentials
scoped as tightly as your PAT provider allows, and treat every PR it opens
with at least as much scrutiny as one from an unfamiliar contributor —
because structurally, that's exactly what it is.
