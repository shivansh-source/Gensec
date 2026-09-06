package fixer

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/flagging"
	"github.com/shivansh-source/gensec/internal/llm"
	"github.com/shivansh-source/gensec/internal/scanner"
)

type BatchFixer struct {
	tracker *AttemptTracker
	scanner *scanner.MultiScanner
}

func NewBatchFixer() *BatchFixer {
	return &BatchFixer{
		tracker: NewAttemptTracker(),
		scanner: scanner.NewMultiScanner(config.UserPlan(), "."),
	}
}

func (bf *BatchFixer) FixFileVulnerabilities(file string, vulns []flagging.Flag, fileContent string) *FixResult {
	result := &FixResult{
		File:           file,
		VulnsFixed:     []flagging.Flag{},
		VulnsFailed:    []flagging.Flag{},
		VulnsEscalated: []flagging.Flag{},
	}

	fmt.Printf("\n🔧 PHASE 4a: BATCH FIX & VERIFY\n")
	fmt.Printf("   File: %s\n", file)
	fmt.Printf("   Vulns to fix: %d\n", len(vulns))

	// Take top N vulns (already sorted by severity)
	batch := vulns
	if len(batch) > config.MaxVulnsPerBatch {
		batch = batch[:config.MaxVulnsPerBatch]
	}

	fmt.Printf("\n   Batch to fix:\n")
	for _, v := range batch {
		fmt.Printf("     - Line %d: %s (%s, %s)\n", v.Line, v.VulnID, v.CWE, v.Severity)
	}

	// Build batch description for LLM
	batchDesc := bf.buildBatchDescription(batch)

	// LLM generates fixes
	fmt.Printf("\n   Calling LLM to generate fixes...\n")
	fixedCode, err := bf.generateFixes(fileContent, batchDesc)
	if err != nil {
		fmt.Printf("   ❌ LLM fix generation failed: %v\n", err)
		result.Status = "failed"
		result.VulnsFailed = batch
		return result
	}

	fixedCode = strings.TrimSpace(fixedCode)
	if fixedCode == "" {
		fmt.Printf("   ❌ Empty fix generated\n")
		result.Status = "failed"
		result.VulnsFailed = batch
		return result
	}

	if fixedCode == fileContent {
		fmt.Printf("   ⚠️  LLM returned unchanged code\n")
		for _, v := range batch {
			bf.tracker.RecordAttempt(v.VulnID, "failed", "LLM returned unchanged code")
			result.VulnsFailed = append(result.VulnsFailed, v)
		}
		result.Status = "failed"
		return result
	}

	// --- Apply fix to disk with rollback safety ---

	originalCode := fileContent
	backupFile := file + ".gensec.bak"

	// Save backup of original
	if err := os.WriteFile(backupFile, []byte(originalCode), 0644); err != nil {
		fmt.Printf("   ⚠️  Failed to write backup file: %v (continuing)\n", err)
	}

	// Write fixed code to real file
	if err := os.WriteFile(file, []byte(fixedCode), 0644); err != nil {
		fmt.Printf("   ❌ Failed to write fixed file: %v\n", err)
		result.Status = "failed"
		result.VulnsFailed = batch
		return result
	}
	fmt.Printf("   💾 Wrote candidate fixed file: %s\n", file)

	// Verify: Re-scan repository with scanners
	fmt.Printf("\n   Verifying fixes...\n")
	verificationResults, err := bf.verifyFixes()
	if err != nil {
		fmt.Printf("   ⚠️  Verification error: %v\n", err)
		// On verification error, restore original code
		_ = os.WriteFile(file, []byte(originalCode), 0644)
		result.Status = "partial"
		result.FixedCode = ""
		result.VulnsFailed = batch
		return result
	}

	// Classify each vuln as fixed / failed / escalated
	for _, vuln := range batch {
		stillPresent := false
		for _, verifiedVuln := range verificationResults {
			if verifiedVuln.VulnID == vuln.VulnID && verifiedVuln.File == file {
				stillPresent = true
				break
			}
		}

		if !stillPresent {
			// Fixed!
			result.VulnsFixed = append(result.VulnsFixed, vuln)
			bf.tracker.RecordAttempt(vuln.VulnID, "fixed", "")
			fmt.Printf("   ✅ Fixed: %s\n", vuln.VulnID)
		} else {
			// Still present → record as failed and maybe escalate
			bf.tracker.RecordAttempt(vuln.VulnID, "failed", "Still detected after LLM fix")
			attempts := bf.tracker.GetAttempts(vuln.VulnID)

			if attempts >= config.MaxAttemptsPerVuln {
				result.VulnsEscalated = append(result.VulnsEscalated, vuln)
				bf.tracker.MarkEscalated(vuln.VulnID)
				fmt.Printf("   🚩 Escalated: %s (attempt %d/%d)\n", vuln.VulnID, attempts, config.MaxAttemptsPerVuln)
			} else {
				result.VulnsFailed = append(result.VulnsFailed, vuln)
				fmt.Printf("   ⚠️  Failed: %s (attempt %d/%d)\n", vuln.VulnID, attempts, config.MaxAttemptsPerVuln)
			}
		}
	}

	// If nothing actually fixed → roll back file
	if len(result.VulnsFixed) == 0 {
		fmt.Printf("   ↩️  No vulnerabilities fixed, restoring original file\n")
		_ = os.WriteFile(file, []byte(originalCode), 0644)
		result.Status = "failed"
		result.FixedCode = ""
	} else {
		// Keep fixed version on disk
		result.FixedCode = fixedCode

		if len(result.VulnsFailed) == 0 && len(result.VulnsEscalated) == 0 {
			result.Status = "success"
		} else {
			result.Status = "partial"
		}
	}

	// Cleanup backup (optional, you can keep it if you want)
	_ = os.Remove(backupFile)

	result.PRDescription = bf.buildPRDescription(result)
	return result
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (bf *BatchFixer) buildBatchDescription(vulns []flagging.Flag) string {
	var b strings.Builder
	for _, v := range vulns {
		fmt.Fprintf(&b, "- Line %d: %s (%s, %s)\n  %s\n\n",
			v.Line, v.VulnID, v.CWE, v.Severity, v.Message)
	}
	return b.String()
}

// ✅ FULL PROMPT DEFINED HERE
func (bf *BatchFixer) generateFixes(originalCode, batchDesc string) (string, error) {
	prompt := fmt.Sprintf(`You are a Go security refactoring engine.

Your job:
- Take the ORIGINAL CODE and the list of VULNERABILITIES TO FIX.
- Apply ONLY minimal, targeted changes needed to remove those vulnerabilities.
- Preserve behavior and public APIs.
- Use idiomatic, production-grade Go.

Important security rules:
- For SQL issues: NEVER build SQL with string concatenation. Use parameterized queries (e.g. db.Query("SELECT ... WHERE name = ?", value)).
- For HTTP/TLS issues: Prefer http.ListenAndServeTLS with proper cert/key arguments instead of http.ListenAndServe.
- For command execution: avoid passing unsanitized user input to shells; prefer parametrized exec or safe whitelisting.

VULNERABILITIES TO FIX:
%s

ORIGINAL CODE:
%s

STRICT OUTPUT RULES:
- Return ONLY the complete, fixed Go source file.
- Do NOT wrap the code in markdown fences.
- Do NOT add explanations or comments about what you did.
- The file must compile as-is.

FIXED CODE:
`, batchDesc, originalCode)

	triager := llm.NewLLMTriager()
	response, err := triager.CallGroqDirect(prompt)
	if err != nil {
		return "", err
	}

	response = strings.TrimSpace(response)

	// Extract code from markdown fences if present
	if strings.Contains(response, "```") {
		start := strings.Index(response, "```go")
		if start == -1 {
			start = strings.Index(response, "```")
		}
		if start != -1 {
			start += 3 // skip ```
			if strings.HasPrefix(response[start:], "go") {
				start += 2 // skip "go"
			}
			end := strings.LastIndex(response, "```")
			if end > start {
				return strings.TrimSpace(response[start:end]), nil
			}
		}
	}

	// Otherwise assume the whole response is just code
	return response, nil
}

// verifyFixes re-runs the scanners against the current workspace on disk.
func (bf *BatchFixer) verifyFixes() ([]flagging.Flag, error) {
	findings, err := bf.scanner.ScanAll()
	if err != nil {
		return nil, err
	}

	flagFindings := make([]flagging.Flag, 0, len(findings))
	for _, f := range findings {
		flagFindings = append(flagFindings, flagging.Flag{
			VulnID:   f.VulnID,
			File:     f.File,
			Line:     f.Line,
			CWE:      f.CWE,
			Severity: f.Severity,
			Message:  f.Message,
		})
	}

	return flagFindings, nil
}

func (bf *BatchFixer) buildPRDescription(result *FixResult) string {
	desc := fmt.Sprintf("## GenSec: Fix %d vulnerabilities in `%s`\n\n",
		len(result.VulnsFixed), result.File)

	if len(result.VulnsFixed) > 0 {
		desc += "### ✅ Fixed Vulnerabilities\n"
		for _, v := range result.VulnsFixed {
			desc += fmt.Sprintf("- **%s** (%s): %s\n", v.VulnID, v.CWE, v.Message)
		}
		desc += "\n"
	}

	if len(result.VulnsFailed) > 0 {
		desc += "### ⚠️ Failed (Will Retry Next Run)\n"
		for _, v := range result.VulnsFailed {
			attempts := bf.tracker.GetAttempts(v.VulnID)
			log := bf.tracker.logs[v.VulnID]
			lastTime := ""
			if log != nil {
				lastTime = log.LastAttempted.Format("2006-01-02 15:04:05")
			}
			desc += fmt.Sprintf("- **%s**: Attempt %d/%d\n", v.VulnID, attempts, config.MaxAttemptsPerVuln)
			desc += fmt.Sprintf("  Last attempted: %s\n", lastTime)
		}
		desc += "\n"
	}

	if len(result.VulnsEscalated) > 0 {
		desc += "### 🚩 Escalated to Human Review\n"
		for _, v := range result.VulnsEscalated {
			attempts := bf.tracker.GetAttempts(v.VulnID)
			desc += fmt.Sprintf(
				"- **%s** (%s): Max attempts (%d/%d) reached\n",
				v.VulnID, v.CWE, attempts, config.MaxAttemptsPerVuln,
			)
		}
		desc += "\n"
	}

	desc += fmt.Sprintf("**Generated:** %s\n", time.Now().Format("2006-01-02 15:04:05"))
	desc += "**Tool:** GenSec Autonomous Security Agent\n"
	desc += "**Status:** ⏳ Awaiting human approval to merge\n"

	return desc
}
