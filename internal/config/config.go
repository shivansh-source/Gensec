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
	GroqModel = "llama-3.3-70b-versatile"
)

var (
	GitHubToken = os.Getenv("GITHUB_TOKEN")
	GitHubUser  = os.Getenv("GITHUB_USER")
	GroqAPIKey  = os.Getenv("GROQ_API_KEY")
	UserPlan    = os.Getenv("USER_PLAN")
	Concurrency = 4
)

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
