package config

import (
	"os"
)

const (
	// Severity levels
	SeverityCRITICAL = "CRITICAL"
	SeverityHIGH     = "HIGH"
	SeverityMEDIUM   = "MEDIUM"
	SeverityLOW      = "LOW"

	// Phase configuration
	MaxVulnsPerBatch   = 5
	MaxAttemptsPerVuln = 3
	MaxPRsPerRun       = 5
	AttemptCooldownHrs = 24

	// File paths
	VulnerableFilePath = "vulnerable_app.go"
	ReportFileSemgrep  = "report_semgrep.json"
	ReportFileGitleaks = "report_gitleaks.json"
	ReportFileTrivy    = "report_trivy.json"
	ReportFileFlagged  = "report_flagged.json"
	AttemptLogFile     = "attempt_log.json"

	// API
	// llama-3.3-70b-versatile was retired from Groq; qwen/qwen3.8-27b is a
	// currently-available model that reliably returns complete (non-reasoning)
	// responses within this package's existing token budgets.
	GroqModel = "qwen/qwen3.8-27b"
)

var Concurrency = 4

// GitHubToken, GitHubUser, GroqAPIKey, and UserPlan read their environment
// variable fresh on every call, rather than caching it once. They used to
// be plain package-level vars initialized via os.Getenv at package-init
// time — but package-level var initialization runs before main() calls
// godotenv.Load(), so a value only set via a .env file (not a real
// exported environment variable) was silently never seen: these vars
// would be permanently empty regardless of what .env contained. Calling
// os.Getenv fresh here fixes that for every caller at once.
func GitHubToken() string { return os.Getenv("GITHUB_TOKEN") }
func GitHubUser() string  { return os.Getenv("GITHUB_USER") }
func GroqAPIKey() string  { return os.Getenv("GROQ_API_KEY") }
func UserPlan() string    { return os.Getenv("USER_PLAN") }

type Severity int

const (
	SevCRITICAL Severity = iota
	SevHIGH
	SevMEDIUM
	SevLOW
)

func (s Severity) String() string {
	switch s {
	case SevCRITICAL:
		return SeverityCRITICAL
	case SevHIGH:
		return SeverityHIGH
	case SevMEDIUM:
		return SeverityMEDIUM
	case SevLOW:
		return SeverityLOW
	default:
		return "UNKNOWN"
	}
}
