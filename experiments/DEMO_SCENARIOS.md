# GenSec Demo Scenarios

Use these scenarios to showcase GenSec during interviews.

## Scenario 1: Quick Vulnerability Scan (2 minutes)

### Setup
```bash
cd examples
export GROQ_API_KEY=demo_key
export USER_PLAN=pro
```
DEMO 
```bash
gensec scan ./vulnerable-code
```
What to Say
"GenSec automatically scans Go codebases and identifies vulnerabilities through multiple phases. Here we're running a scan which:

Phase 1 - Uses SAST, pattern matching, and static analysis to find 12 potential issues
Phase 2 - Analyzes data flow to reduce false positives (down to 8)
Phase 3 - Uses LLM to score confidence (down to 6 high-confidence findings)
Notice how we went from 12 findings → 8 → 6 by being smarter about detection?"

Key Points
Show the vulnerabilities it finds (SQL injection, hardcoded secrets, path traversal)
Explain the data flow analysis reduces noise
Mention the LLM confidence scoring filters false positives
Scenario 2: Automated Fix Generation (2 minutes)
Demo
bash
gensec fix
What to Say
"Now GenSec moves to Phase 4: Batch Fixing. The tool:

Reads the flagged vulnerabilities from the previous scan
Uses the LLM to generate security patches
Verifies fixes don't break the code
Groups all changes for a GitHub PR
The fixes are production-ready and follow Go best practices."

Key Points
Show the generated PR body with fix descriptions
Mention it's LLM-powered code generation
Explain verification prevents breaking changes
Scenario 3: GitHub PR Creation (1 minute)
Setup
bash
export GITHUB_TOKEN=ghp_your_token
export GITHUB_USER=your-username
export GITHUB_REPO=owner/repo
Demo
bash
gensec pr
What to Say
"Finally, Phase 5 automatically creates a pull request on GitHub with:

All vulnerability fixes
Detailed descriptions of each fix
Links to security analysis
Ready for code review"
Key Points
Show the PR URL that's generated
Mention it's fully automated
Explain how this reduces security overhead
Scenario 4: One-Command Pipeline (3 minutes)
Demo - The Impressive One
bash
gensec scan-and-fix ./vulnerable-code
What to Say
"This single command orchestrates the entire security pipeline:

Scan → Identify vulnerabilities Flag → Reduce false positives
Triage → LLM confidence scoring Fix → Generate patches PR → Create GitHub pull request

All in one command. Fully automated security remediation."

Key Points
Shows the complete architecture
Demonstrates automation value
Impresses with speed and comprehensiveness
Scenario 5: Plan Tiers & Customization (1 minute)
Demo Different Plans
bash
export USER_PLAN=free
gensec scan ./vulnerable-code

export USER_PLAN=pro
gensec scan ./vulnerable-code

export USER_PLAN=enterprise
gensec scan ./vulnerable-code
What to Say
"GenSec supports three plan tiers:

Free: Basic SAST scanning with limited flagging
Pro: Enhanced data flow analysis + LLM triage (best for most teams)
Enterprise: Full feature set with priority support and batch processing
You can see how each plan progressively enables more sophisticated analysis."

Scenario 6: Docker Deployment (1 minute)
Demo
bash
docker build -t gensec .
docker run -e GROQ_API_KEY=gsk_... \
           -e GITHUB_TOKEN=ghp_... \
           -v $(pwd):/scan \
           gensec scan-and-fix /scan
What to Say
"GenSec works in CI/CD pipelines via Docker:

Containerized for consistency
Integrates with GitHub Actions
Scales to enterprise deployments
Zero dependencies beyond Go 1.24+"
Technical Talking Points
Architecture
Multi-phase design for accuracy
Data flow analysis reduces false positives by 30-40%
LLM integration provides intelligent triage
Modular codebase: easy to extend
Security Features
SQL injection detection
Hardcoded secrets detection
Path traversal prevention
Template injection prevention
And more...
Production Ready
Clean Go code with error handling
Proper logging and audit trails
GitHub integration
Configuration via environment variables
