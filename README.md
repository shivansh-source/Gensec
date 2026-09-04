# 🤖 GenSec Pro v3 - Autonomous Vulnerability Fixer with Data Flow Flagging

A powerful Go-based security scanning and automated remediation tool that identifies, flags, triages, and fixes vulnerabilities in Go codebases using advanced data flow analysis and LLM-powered decision making.

## 🎯 Overview

GenSec is an autonomous security agent that performs multi-phase vulnerability detection and remediation:

1. **Scanning** - Multi-scanner vulnerability detection
2. **Data Flow Flagging** - Context-aware vulnerability analysis  
3. **LLM Triage** - Confidence scoring using AI (Groq API)
4. **Batch Fixing** - Automated vulnerability remediation
5. **PR Creation** - Automated GitHub pull request generation

## 📋 Features

- **Multi-Scanner Support** - Comprehensive vulnerability detection
- **Data Flow Analysis** - Intelligent flagging of security issues in context
- **LLM-Powered Triage** - AI-based confidence scoring (requires GROQ_API_KEY)
- **Batch Fixing** - Automated remediation with verification
- **GitHub Integration** - Direct PR creation for fixes
- **Plan-Based Scanning** - Free, Pro, and Enterprise tier support
- **One-Command Pipeline** - `scan-and-fix` for complete workflow

## 🚀 Quick Start

### One command, one config file

```bash
git clone https://github.com/shivansh-source/gensec.git && cd gensec
cp .env.example .env   # fill in GROQ_API_KEY at minimum
docker run --rm --env-file .env -v "$(pwd)/examples/vulnerable-code:/scan" shivansh-source/gensec:latest scan /scan
```

That finds real vulnerabilities in the bundled example code in a few
seconds — Semgrep, Gitleaks, Trivy, and GenSec's own pattern matcher all run
inside the image, so nothing else needs to be installed locally. No GitHub
credentials are needed for this first step.

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

See [deploy/k8s/cronjob.yaml](deploy/k8s/cronjob.yaml) for the full manifest
and what it assumes (it clones `GITHUB_REPO` into an `emptyDir` via an init
container, then runs `scan-and-fix` against that clone).

### Prerequisites

- **Docker** — for the quickstart above (recommended; bundles Semgrep, Gitleaks, and Trivy)
- **Groq API Key** — for LLM triage and fix generation
- **GitHub PAT** — for PR creation only
- **Go 1.24.5+** and **kubectl** — only needed for building from source or deploying to Kubernetes

### Building from source

```bash
git clone https://github.com/shivansh-source/gensec.git
cd gensec
go build -o gensec ./cmd/gensec
```

Building from source does **not** install Semgrep, Gitleaks, or Trivy.
`gensec scan` currently fails silently (reports 0 findings, no warning) for
any of the three that isn't on your `PATH` — install them yourself, or use
the Docker image, which bundles all three.

### Configuration

```bash
export GROQ_API_KEY=gsk_...                          # Required for scanning
export GITHUB_TOKEN=ghp_...                          # Required for PR creation
export GITHUB_USER=your-github-username              # GitHub username
export GITHUB_REPO=owner/repo-name                   # Target repository
export USER_PLAN=pro                                 # free|pro|enterprise
```

Or put the same variables in a `.env` file at the repo root (see
`.env.example`) — GenSec loads it automatically on startup.
## 📖 Commands
### Scan for Vulnerabilities
bash
gensec scan [path]
Scans Go files for vulnerabilities and generates flagged findings with LLM triage.

### Fix Vulnerabilities
bash
gensec fix
Batch fixes vulnerabilities from previous scan results.

### Create GitHub PR
bash
gensec pr
Creates a pull request on GitHub with all fixes.

### Complete Pipeline
bash
gensec scan-and-fix [path]
Runs the entire workflow: scan → fix → PR creation in one command.

### check Status
bash
gensec status
Displays current scan status and pending findings.

🔄 Workflow
```
Code
┌─────────────┐
│   PHASE 1   │ Multi-Scanner Detection
└──────┬──────┘
       │
       ├─ SAST Scanning
       ├─ Pattern Matching
       └─ Static Analysis
       │
┌──────▼──────┐
│   PHASE 2   │ Data Flow Flagging
└──────┬──────┘
       │
       ├─ Context Analysis
       ├─ Data Flow Tracing
       └─ Vulnerability Classification
       │
┌──────▼──────┐
│   PHASE 3   │ LLM Triage
└──────┬──────┘
       │
       ├─ AI-Powered Scoring
       ├─ Confidence Filtering
       └─ Priority Assignment
       │
┌──────▼──────┐
│   PHASE 4   │ Batch Fixing & Verification
└──────┬──────┘
       │
       ├─ Automated Remediation
       ├─ Code Generation
       └─ Verification
       │
┌──────▼──────┐
│   PHASE 5   │ GitHub PR Creation
└─────────────┘
```
📁 Project Structure
Code
gensec/
├── cmd/
│   └── gensec/
│       └── main.go              # Entry point
├── internal/
│   ├── config/                  # Configuration management
│   ├── scanner/                 # Multi-scanner implementation
│   ├── flagging/                # Data flow flagging engine
│   ├── llm/                      # LLM triage integration
│   ├── fixer/                    # Batch vulnerability fixer
│   └── github/                   # GitHub API client
├── Dockerfile                    # Container support
└── go.mod / go.sum              # Dependencies
🔧 Configuration
Plan Tiers
free - Basic scanning with limited flagging
pro - Enhanced data flow analysis with LLM triage
enterprise - Full feature set with priority support
Report Files
gensec_flags.json - Flagged vulnerabilities after data flow analysis
gensec_pr_body.md - Generated PR description (auto-created by fix phase)
gensec_attempts.log - Attempt tracking log
📦 Dependencies
github.com/joho/godotenv - Environment variable loading
🐳 Docker Support
See "Quick Start" above for the maintained Docker and Kubernetes commands —
this section used to duplicate an older, incomplete version of them.
🔐 Security Considerations
Keep API keys secure - use environment variables or secrets management
Review generated fixes before merging PRs
Configure branch protections for security-related changes
Monitor GenSec execution logs for suspicious activity
📊 Example Output
Code
## 🚀 GenSec Pro v3 - Data Flow Flagging Scanner
============================================================
Plan: pro
📂 Scan root: .
📁 Loaded 5 files

🔍 Phase 1: Multi-Scanner Detection
✅ SAST Scanner: 12 findings

🔍 Phase 2: Data Flow Flagging  
✅ Flagging Complete: 8 vulnerabilities flagged

🔍 Phase 3: LLM Triage
✅ Triage Complete: 6 high-confidence findings (60%+ confidence)

============================================================
✅ SCAN COMPLETE
============================================================
Total findings (all scanners): 12
After data-flow flagging: 8
After LLM triage (confidence >= 60%): 6
🤝 Contributing
Contributions are welcome! Please ensure:

Code passes Go linting standards
New features include appropriate tests
Security implications are documented
📄 License
See repository for license details.

