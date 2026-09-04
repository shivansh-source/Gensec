# GenSec

GenSec scans Go repositories for vulnerabilities, uses an LLM to triage and
patch the ones worth fixing, and opens a GitHub pull request with the
result — for teams who want vulnerabilities remediated, not just listed.

![GenSec demo](docs/demo.gif)

*(placeholder — demo GIF showing a scan finding a vulnerability, GenSec
generating a fix, and the resulting PR)*

## Why does this exist

Most scanning tools stop at detection. Dependabot tells you a dependency
has a CVE and offers a version bump; Snyk and Semgrep tell you a pattern
matched a known-bad shape. For a large class of real vulnerabilities —
SQL injection built from string concatenation, a hardcoded secret, a path
traversal in a file handler — there is no version to bump. Someone has to
read the finding, understand the surrounding code, write an actual patch,
and open a PR. That triage-to-patch step is manual, unglamorous, and where
a lot of known vulnerabilities sit untouched for months, not because no
tool found them, but because finding them was never the hard part.

GenSec's bet is that this specific step — "here is a flagged line and its
context, write a fix" — is exactly the kind of mechanical, well-scoped
task an LLM is reasonably good at, as long as it's kept on a short leash:
fed a specific, narrow finding rather than "find bugs in this file", and
never trusted to merge its own work. So GenSec doesn't try to replace
Semgrep, Gitleaks, or Trivy — it runs them, plus a small pattern matcher of
its own, and uses the LLM only for the two steps traditional scanners
don't do: judging whether a flagged pattern is worth fixing in context, and
generating the patch text. A human still reviews and merges the PR.

This is a young, opinionated tool, not a mature security product. The
[Limitations](#limitations) section below is not boilerplate — read it
before pointing this at anything you care about.

## Quick Start

### One command, one config file

```bash
git clone https://github.com/shivansh-source/gensec.git && cd gensec
cp .env.example .env   # fill in GROQ_API_KEY at minimum
docker run --rm --env-file .env -v "$(pwd)/examples/vulnerable-code:/scan" shivansh-source/gensec:latest scan /scan
```

That finds real vulnerabilities in the bundled example code in a few
seconds. Semgrep, Gitleaks, Trivy, and GenSec's own pattern matcher all run
inside the image, so nothing else needs to be installed locally, and no
GitHub credentials are needed for this first step.

To run the full pipeline (scan → fix → open a PR), mount a real git clone
of the repo you want fixed instead of the bundled example — the `pr` step
needs an actual git history and a remote to push to, which a bare folder
doesn't have:

```bash
git clone https://github.com/<you>/<target-repo>.git target
docker run --rm --env-file .env -v "$(pwd)/target:/scan" shivansh-source/gensec:latest scan-and-fix /scan
```

`GITHUB_REPO` in `.env` must match `<you>/<target-repo>`, and `GITHUB_TOKEN`
needs push access to it.

### Deploying to Kubernetes

GenSec has no Kubernetes-API integration of its own — it's a CLI, not an
operator or controller — but the same image can run in-cluster on a
schedule via a plain CronJob:

```bash
kubectl create namespace gensec
kubectl create secret generic gensec-secrets -n gensec --from-env-file=.env
kubectl apply -f deploy/k8s/cronjob.yaml
```

See [deploy/k8s/cronjob.yaml](deploy/k8s/cronjob.yaml) for the full manifest.
It clones `GITHUB_REPO` into an `emptyDir` via an init container, then runs
`scan-and-fix` against that clone.

### Building from source

```bash
git clone https://github.com/shivansh-source/gensec.git
cd gensec
go build -o gensec ./cmd/gensec
```

Building from source does **not** install Semgrep, Gitleaks, or Trivy.
`gensec scan` currently fails silently (reports 0 findings from that
scanner, no warning) for any of the three that isn't on your `PATH` — see
Limitations. Install them yourself, or use the Docker image.

## Architecture

GenSec is a CLI, not a daemon. Each subcommand (`scan`, `fix`, `pr`) is a
separate process invocation; state between them is passed via JSON files
written to the current directory (`report_flagged.json`, `attempt_log.json`,
`gensec_pr_body.md`), not held in memory. `scan-and-fix` just runs the three
in sequence inside one process.

**1. Scanning** (`internal/scanner`) — `MultiScanner.ScanAll` runs four
detectors concurrently: Semgrep, Gitleaks, and Trivy as external processes
(via `os/exec`, parsing their JSON output), plus an in-process regex/
substring pattern matcher (`GenSecPatterns`) covering a fixed set of CWE
categories — SQL injection via string concatenation or `fmt.Sprintf`,
unparameterized `db.Query(query)` calls, shell command injection,
path traversal on a couple of hardcoded upload paths, unrestricted file
upload, and naive heuristics for CSRF, unbounded loops, hardcoded secrets,
and sensitive logging. Results are merged and deduplicated by
`file:line:CWE`.

**2. Flagging** (`internal/flagging`) — for each finding, `AnalyzeFinding`
looks at a single line of surrounding code for a "source" pattern (user
input: URL params, form values, env vars, etc.) and a "sink" pattern
(a DB call, shell exec, HTTP response write, etc.), and separately scans
the whole file for anything that looks like a sanitizer. This is
line-based pattern matching, not AST-based dataflow or taint tracking —
see Limitations for what that means in practice. It produces a heuristic
confidence score per finding.

**3. LLM triage** (`internal/llm`) — each flagged finding is sent to
Groq's chat-completions API with a prompt asking for a real-vs-false-positive
judgment and a 0.0–1.0 confidence score. Findings below 0.6 confidence are
dropped. If the API call fails, the finding is kept with its confidence
reduced by 20% rather than dropped outright; if the model's response isn't
parseable JSON, it falls back to a default 0.5 confidence (which is itself
below the keep threshold).

**4. Batch fixing** (`internal/fixer`) — for surviving findings, grouped by
file, the same LLM is prompted to return a complete replacement for the
file. If the returned text differs from the original, it's written to
disk, and the scanners from step 1 are re-run against it. If a
previously-flagged vulnerability ID no longer appears, it's marked fixed;
otherwise it's retried up to `MaxAttemptsPerVuln` (3) times before being
escalated. This re-scan is the only verification step — nothing checks
that the file still compiles.

**5. PR creation** (`internal/github`) — `CreatePRForCurrentChanges` shells
out directly to the `git` binary (checkout a `gensec/fix-<timestamp>`
branch, commit, push to a token-authenticated HTTPS URL) and then calls
GitHub's REST API directly over `net/http` to open the PR. There's no
`gh` CLI dependency and no GitHub SDK.

## Configuration

GenSec has no config file format of its own — everything is environment
variables, loaded from a `.env` file in the working directory if one
exists (see `.env.example`).

| Variable | Required for | Notes |
|---|---|---|
| `GROQ_API_KEY` | `scan`, `fix` | Groq API key. `scan` refuses to run at all without it, even though only the LLM-triage phase actually needs it. |
| `GITHUB_TOKEN` | `pr` | Needs direct push access to `GITHUB_REPO` — classic PAT with `repo` scope, or fine-grained with Contents (read/write) + Pull requests (read/write). There is no fork-and-PR fallback. |
| `GITHUB_USER` | `pr` | Used as the git commit author and in the push URL. |
| `GITHUB_REPO` | `pr` | `owner/repo`. Must match the git remote of whatever directory you're running against. |
| `GITHUB_BASE_BRANCH` | optional | PR base branch. Defaults to `main`. |
| `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` | optional | Overrides the commit author derived from `GITHUB_USER`. |
| `USER_PLAN` | optional | `free`, `pro`, or `enterprise`. Defaults to empty (treated as `free`). |

`USER_PLAN` currently only changes which Semgrep rule packs run: `free`
gets `p/gosec` + `p/owasp-top-ten`; `pro` and `enterprise` additionally get
`p/security-audit` + `p/cwe-top-25`. `pro` and `enterprise` are otherwise
identical today — the tiering exists in config but not yet in behavior
beyond that one flag.

## Limitations

- **Scanners fail silently, not loudly.** If the `gitleaks` or `trivy`
  binaries aren't on `PATH`, GenSec reports 0 findings from them with no
  error — a clean scan can mean "no vulnerabilities" or "two of four
  scanners never ran." The Docker image bundles all three; running from a
  source build does not.
- **The "data flow" analysis is line-level pattern matching**, not AST-based
  taint analysis. Source and sink must appear on the same single line to
  be linked; a sanitizer call is detected by the sanitized variable's name
  appearing anywhere in the file, with no control-flow or scope awareness.
  It also currently misreads which line to analyze for findings on
  roughly the first 6 lines of a file.
- **The built-in pattern matcher's rules are narrow.** It checks a fixed
  list of CWE categories with fairly specific string/regex matches (e.g.
  hardcoded upload paths, an exact loop shape for the DoS heuristic) — it
  is not a general-purpose SAST engine, and some of its heuristics are
  noisy (a hardcoded-secret check matches the substring `sk-`, which
  false-positives on ordinary words like "risk-based").
- **Trivy findings can be silently deduplicated away.** The dedup key
  includes line number and CWE, but every Trivy finding reports line 0 and
  an unknown CWE — so multiple distinct CVEs on the same file currently
  collapse into a single surviving finding.
- **No compile or test check before a fix is committed.** LLM-generated
  code is written straight to disk; the only verification is re-running
  the scanners to see if the original vulnerability signature still
  matches. A syntactically broken patch that happens not to re-trigger the
  pattern would be marked "fixed" and pushed. See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full trust model.
- **Go only.** Both the pattern matcher and the flagging heuristics assume
  Go source.
- **One target repo per run**, pushed directly to a real branch on
  `GITHUB_REPO` with no draft-PR or dry-run mode — the PR itself is the
  review gate, not anything before it.
- **Groq only.** The LLM integration is hardcoded to Groq's
  chat-completions API; there's no provider abstraction.

## Roadmap

- Replace the line-level source/sink heuristics with real AST-based
  dataflow analysis, which would also fix the top-of-file line
  misattribution bug.
- Add a build/test gate (at minimum `go build`, ideally the target repo's
  own test suite) before a fix is committed, so a syntactically broken LLM
  patch can never reach a PR on the strength of a re-scan alone.
- Support additional languages and additional LLM providers beyond Go and
  Groq.

## Contributing

```
gensec/
├── cmd/gensec/          # CLI entry point and command wiring
├── internal/
│   ├── config/          # env-var-based configuration
│   ├── scanner/         # Semgrep/Gitleaks/Trivy + pattern-matcher detection
│   ├── flagging/        # source/sink/sanitizer heuristics, confidence scoring
│   ├── llm/             # Groq prompt building, calls, response parsing
│   ├── fixer/           # LLM-driven patch generation, attempt tracking
│   └── github/          # git CLI + GitHub REST API PR creation
├── examples/vulnerable-code/  # sample vulnerable Go files used in the demo
├── deploy/k8s/          # Kubernetes CronJob manifest
└── docs/                # threat model, etc.
```

Run the test suite with:

```bash
go test ./...
go vet ./...
gofmt -l .
```

Tests are table-driven where the logic is table-shaped (detection rules,
response parsing, retry thresholds) and use mocked HTTP transports for the
Groq and GitHub API calls — no real network access or API keys are needed
to run them. See the comments in `internal/github/client_test.go` for what
isn't covered and why (the PR-creation path shells out to real `git`
commands with no injectable seam for testing it end-to-end).
