# GenSec - Interview Demo Guide

## Quick Start Demo Commands

This guide shows you how to run GenSec for a live interview demo.

### 1. **Setup Environment Variables**
```bash
export GROQ_API_KEY=gsk_demo_key_12345
export GITHUB_TOKEN=ghp_demo_token_67890
export GITHUB_USER=your-username
export GITHUB_REPO=owner/repo-name
export USER_PLAN=pro
```

### 2. **Build GenSec**
```bash
go build -o gensec ./cmd/gensec
```

### 3. **Run Demo Scan** (Shows Phase 1-3)
```bash
./gensec scan ./examples/vulnerable-code
```
Expected output:
- Shows 12 SAST findings
- Data flow flagging reduces to 8 vulnerabilities
- LLM triage filters to 6 high-confidence issues

### 4. **Run Batch Fix** (Shows Phase 4)
```bash
./gensec fix
```
Expected output:
- Reads `gensec_flags.json` from previous scan
- Shows automated remediation for each vulnerability
- Generates `gensec_pr_body.md`

### 5. **Create GitHub PR** (Shows Phase 5)
```bash
./gensec pr
```
Expected output:
- Creates a PR on GitHub
- Links to the PR URL

### 6. **One-Command Demo** (All Phases)
```bash
./gensec scan-and-fix ./examples/vulnerable-code
```

## Demo Talking Points

### Architecture
1. **Multi-Phase Architecture**: Scan → Flag → Triage → Fix → PR
2. **Data Flow Analysis**: Contextual vulnerability assessment
3. **LLM Integration**: Groq API for intelligent confidence scoring
4. **Automated Remediation**: LLM-powered code generation

### Key Features
- ✅ Multi-scanner support (SAST, pattern matching, static analysis)
- ✅ Data flow analysis for context-aware flagging
- ✅ LLM-powered confidence scoring
- ✅ Batch vulnerability fixing with verification
- ✅ Automated GitHub PR creation
- ✅ Plan-based tiering (free/pro/enterprise)

### Code Quality
- Clean Go architecture with clear separation of concerns
- Modular design: `internal/scanner`, `internal/flagging`, `internal/llm`, `internal/fixer`, `internal/github`
- Proper error handling and logging
- Dockerized for easy deployment

## Demo Files
- `examples/vulnerable-code/` - Sample vulnerable Go files
- `gensec_flags.json` - Output from scan phase (mock data available)
- `gensec_pr_body.md` - Generated PR description

## Expected Demo Flow
1. Show the architecture diagram from README
2. Run `scan-and-fix` on vulnerable code
3. Explain each phase as output appears
4. Show the generated PR on GitHub
5. Discuss how it reduces false positives through data flow flagging
