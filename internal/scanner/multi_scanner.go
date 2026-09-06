package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/shivansh-source/gensec/internal/config"
)

type MultiScanner struct {
	plan     string
	scanRoot string
}

func NewMultiScanner(plan string, scanRoot string) *MultiScanner {
	return &MultiScanner{plan: plan, scanRoot: scanRoot}
}

func (m *MultiScanner) ScanAll() ([]Finding, error) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 PHASE 1: MULTI-SCANNER DETECTION")
	fmt.Println(strings.Repeat("=", 60))

	allFindings := []Finding{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	scanners := []struct {
		name string
		fn   func() ([]Finding, error)
	}{
		{"Semgrep", m.runSemgrep},
		{"Gitleaks", m.runGitleaks},
		{"Trivy", m.runTrivy},
		{"GenSecPatterns", m.runGenSecPatterns},
	}

	for _, scanner := range scanners {
		wg.Add(1)
		go func(s struct {
			name string
			fn   func() ([]Finding, error)
		}) {
			defer wg.Done()
			findings, err := s.fn()
			if err != nil {
				fmt.Printf("⚠️  %s error: %v\n", s.name, err)
				return
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(scanner)
	}

	wg.Wait()

	allFindings = m.deduplicate(allFindings)

	sort.Slice(allFindings, func(i, j int) bool {
		severityOrder := map[string]int{
			config.SeverityCRITICAL: 0,
			config.SeverityHIGH:     1,
			config.SeverityMEDIUM:   2,
			config.SeverityLOW:      3,
		}
		if severityOrder[allFindings[i].Severity] != severityOrder[allFindings[j].Severity] {
			return severityOrder[allFindings[i].Severity] < severityOrder[allFindings[j].Severity]
		}
		return allFindings[i].File < allFindings[j].File
	})

	fmt.Printf("✅ Total findings: %d\n", len(allFindings))
	fmt.Println("   Sorted by severity (CRITICAL → HIGH → MEDIUM → LOW)")

	return allFindings, nil
}

func (m *MultiScanner) runSemgrep() ([]Finding, error) {
	findings := []Finding{}

	if _, err := os.Stat(config.ReportFileSemgrep); err == nil {
		os.Remove(config.ReportFileSemgrep)
	}

	cmd := []string{
		"semgrep",
		"--config", "p/gosec",
		"--config", "p/owasp-top-ten",
	}

	if m.plan == "pro" || m.plan == "enterprise" {
		cmd = append(cmd, "--config", "p/security-audit", "--config", "p/cwe-top-25")
	}

	cmd = append(cmd, "--json", "-o", config.ReportFileSemgrep, ".")

	if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
		return findings, fmt.Errorf("semgrep failed: %w", err)
	}

	data, err := os.ReadFile(config.ReportFileSemgrep)
	if err != nil {
		return findings, nil
	}

	var report struct {
		Results []struct {
			Path  string `json:"path"`
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
			CheckID string `json:"check_id"`
			Extra   struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Lines    string `json:"lines"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return findings, nil
	}

	for _, r := range report.Results {
		finding := Finding{
			Tool:     "semgrep",
			File:     r.Path,
			Line:     r.Start.Line,
			VulnID:   r.CheckID,
			CWE:      m.extractCWE(r.CheckID),
			Message:  r.Extra.Message,
			Severity: r.Extra.Severity,
			Snippet:  r.Extra.Lines,
		}
		findings = append(findings, finding)
	}

	fmt.Printf("  ✅ Semgrep: %d findings\n", len(findings))
	return findings, nil
}

func (m *MultiScanner) runGitleaks() ([]Finding, error) {
	findings := []Finding{}

	if _, err := os.Stat(config.ReportFileGitleaks); err == nil {
		os.Remove(config.ReportFileGitleaks)
	}

	cmd := exec.Command("gitleaks", "detect", "--source", ".", "--json", "-o", config.ReportFileGitleaks, "--no-git")
	cmd.Run()

	data, err := os.ReadFile(config.ReportFileGitleaks)
	if err != nil {
		return findings, nil
	}

	var report []struct {
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
		RuleID    string `json:"RuleID"`
		Match     string `json:"Match"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return findings, nil
	}

	for _, r := range report {
		finding := Finding{
			Tool:     "gitleaks",
			File:     r.File,
			Line:     r.StartLine,
			VulnID:   "gitleaks-" + r.RuleID,
			CWE:      "CWE-798",
			Message:  fmt.Sprintf("Hardcoded secret: %s", r.RuleID),
			Severity: config.SeverityCRITICAL,
			Snippet:  r.Match,
		}
		findings = append(findings, finding)
	}

	fmt.Printf("  ✅ Gitleaks: %d findings\n", len(findings))
	return findings, nil
}

func (m *MultiScanner) runTrivy() ([]Finding, error) {
	findings := []Finding{}

	if _, err := os.Stat(config.ReportFileTrivy); err == nil {
		os.Remove(config.ReportFileTrivy)
	}

	cmd := exec.Command("trivy", "fs", ".", "--format", "json", "-o", config.ReportFileTrivy, "--severity", "HIGH,CRITICAL")
	cmd.Run()

	data, err := os.ReadFile(config.ReportFileTrivy)
	if err != nil {
		return findings, nil
	}

	var report struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Title           string `json:"Title"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return findings, nil
	}

	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			finding := Finding{
				Tool:     "trivy",
				File:     r.Target,
				Line:     0,
				VulnID:   v.VulnerabilityID,
				CWE:      "CWE-Unknown",
				Message:  v.Title,
				Severity: v.Severity,
			}
			findings = append(findings, finding)
		}
	}

	fmt.Printf("  ✅ Trivy: %d findings\n", len(findings))
	return findings, nil
}

func (m *MultiScanner) runGenSecPatterns() ([]Finding, error) {
	findings := []Finding{}

	walkRoot := m.scanRoot
	if walkRoot == "" {
		walkRoot = "."
	}

	// Walk all .go files in the scan root
	err := filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip on error, don't kill the whole scan
		}
		if info.IsDir() {
			// Skip vendor, node_modules, .git, etc. - but never the walk
			// root itself. When walkRoot is exactly ".", filepath.Walk
			// reports it with Name() == ".", which would otherwise match
			// the hidden-dir check and skip the whole tree immediately.
			base := info.Name()
			if path != walkRoot && (strings.HasPrefix(base, ".") || base == "vendor" || base == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		lines := strings.Split(content, "\n")

		for i, line := range lines {
			lineNo := i + 1
			trim := strings.TrimSpace(line)

			// --- CWE-89: SQL Injection (string concatenation in queries) ---
			if (strings.Contains(trim, `"SELECT`) || strings.Contains(trim, `"INSERT`) ||
				strings.Contains(trim, `"UPDATE`) || strings.Contains(trim, `"DELETE`)) &&
				(strings.Contains(trim, `" + `) || strings.Contains(trim, `+"`) ||
					strings.Contains(trim, `+ "`) || strings.Contains(trim, `+userInput`) ||
					strings.Contains(trim, `+ userInput`)) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.sqli.string-concat",
					CWE:      "CWE-89",
					Message:  "SQL query built by string concatenation with user input; possible SQL injection.",
					Severity: config.SeverityCRITICAL,
					Snippet:  trim,
				})
			}

			// --- CWE-89: SQL Injection via fmt.Sprintf ---
			if strings.Contains(trim, "fmt.Sprintf(") &&
				(strings.Contains(trim, "SELECT") || strings.Contains(trim, "INSERT") ||
					strings.Contains(trim, "UPDATE") || strings.Contains(trim, "DELETE")) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.sqli.sprintf",
					CWE:      "CWE-89",
					Message:  "SQL query built using fmt.Sprintf with user data; use parameterized queries instead.",
					Severity: config.SeverityCRITICAL,
					Snippet:  trim,
				})
			}

			// --- CWE-89: Unparameterized db.Query/db.Exec call ---
			// Heuristic: db.Query(query) where `query` is a local var (no second arg on same line)
			if (strings.HasPrefix(trim, "db.Query(query)") ||
				strings.HasPrefix(trim, "rows, err := db.Query(query)") ||
				trim == "db.Query(query)" || strings.Contains(trim, "db.Query(query)")) &&
				!strings.Contains(trim, "db.Query(query,") {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.sqli.unparameterized-query",
					CWE:      "CWE-89",
					Message:  "db.Query called with a raw (possibly interpolated) query string; use parameterized queries.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-78: Command Injection (exec.Command with shell) ---
			if strings.Contains(trim, `exec.Command("sh", "-c"`) ||
				strings.Contains(trim, `exec.Command("bash", "-c"`) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.command-injection.exec-command",
					CWE:      "CWE-78",
					Message:  "Possible OS command injection via exec.Command with shell (\"sh\"/\"bash\" and \"-c\").",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-22: Path Traversal — user-controlled path joined without clean check ---
			if (strings.Contains(trim, `"/uploads/"`) || strings.Contains(trim, `"/var/www/files/"`)) &&
				(strings.Contains(trim, " + ") || strings.Contains(trim, `filepath.Join`)) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.path-traversal.user-path",
					CWE:      "CWE-22",
					Message:  "User-controlled value joined to a base path without sanitization; possible path traversal.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-22: ioutil.ReadFile / os.ReadFile with user-derived path ---
			if strings.Contains(trim, `ioutil.ReadFile(filePath)`) ||
				strings.Contains(trim, `os.ReadFile("/var/www/files/`) ||
				strings.Contains(trim, `os.ReadFile("/uploads/`) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.path-traversal.file-read",
					CWE:      "CWE-22",
					Message:  "User-controlled file path used in ReadFile without sanitization; possible path traversal.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-434: Unrestricted File Upload ---
			if strings.Contains(trim, `r.FormFile("file"`) ||
				strings.Contains(trim, `r.FormFile("picture"`) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.file-upload.unrestricted",
					CWE:      "CWE-434",
					Message:  "Possible unrestricted file upload via r.FormFile without content-type or extension validation.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}
			if strings.Contains(trim, `os.WriteFile("/uploads/`) ||
				strings.Contains(trim, `os.WriteFile("/public/uploads/`) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.file-upload.write-unsafe-path",
					CWE:      "CWE-434",
					Message:  "File written to uploads directory using user-controlled filename; validate type and path.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-352: CSRF (very heuristic) ---
			// Any handler using PostFormValue but no obvious CSRF check nearby.
			if strings.Contains(trim, "PostFormValue(") &&
				!strings.Contains(strings.ToLower(trim), "csrf") {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.csrf.missing-token",
					CWE:      "CWE-352",
					Message:  "POST handler uses form data but no CSRF token is referenced; possible CSRF risk.",
					Severity: config.SeverityHIGH,
					Snippet:  trim,
				})
			}

			// --- CWE-400: Uncontrolled resource consumption (simple loop heuristic) ---
			if strings.Contains(trim, "for i := 0; i < num; i++") {
				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.dos.unbounded-loop",
					CWE:      "CWE-400",
					Message:  "Loop bound is controlled by user input without upper limit; possible DoS risk.",
					Severity: config.SeverityMEDIUM,
					Snippet:  trim,
				})
			}

			// --- CWE-798: Hardcoded secrets ---
			if strings.Contains(trim, `"AKIA`) ||
				strings.Contains(trim, `ghp_`) ||
				strings.Contains(trim, `sk_live_`) ||
				strings.Contains(trim, `sk-`) ||
				strings.Contains(trim, `"hooks.slack.com`) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.hardcoded-secret.literal",
					CWE:      "CWE-798",
					Message:  "Possible hardcoded secret (AWS key, GitHub token, Stripe key, or Slack webhook).",
					Severity: config.SeverityCRITICAL,
					Snippet:  trim,
				})
			}

			// --- CWE-117: Sensitive data logged (connection strings, passwords) ---
			if (strings.Contains(trim, "fmt.Println(") || strings.Contains(trim, "log.Print")) &&
				(strings.Contains(strings.ToLower(trim), "password") ||
					strings.Contains(strings.ToLower(trim), "connectionstring") ||
					strings.Contains(strings.ToLower(trim), "secret")) {

				findings = append(findings, Finding{
					Tool:     "gensec-patterns",
					File:     path,
					Line:     lineNo,
					VulnID:   "gensec.logging.sensitive-data",
					CWE:      "CWE-117",
					Message:  "Sensitive data (password/secret/connection string) may be logged to stdout.",
					Severity: config.SeverityMEDIUM,
					Snippet:  trim,
				})
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("⚠️  GenSecPatterns walker error: %v\n", err)
	}

	fmt.Printf("  ✅ GenSecPatterns: %d findings\n", len(findings))
	return findings, nil
}

func (m *MultiScanner) deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	deduped := []Finding{}

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.CWE)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}

	return deduped
}

func (m *MultiScanner) extractCWE(checkID string) string {
	cweMap := map[string]string{
		"G201": "CWE-89",
		"G202": "CWE-89",
		"G204": "CWE-78",
		"G301": "CWE-434",
		"G302": "CWE-434",
		"G304": "CWE-434",
		"G305": "CWE-434",
	}

	parts := strings.Split(checkID, ".")
	if len(parts) > 0 {
		if cwe, ok := cweMap[parts[len(parts)-1]]; ok {
			return cwe
		}
	}

	return "CWE-Unknown"
}
