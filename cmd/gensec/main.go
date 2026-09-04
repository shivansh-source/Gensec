package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/fixer"
	"github.com/shivansh-source/gensec/internal/flagging"
	gh "github.com/shivansh-source/gensec/internal/github"
	"github.com/shivansh-source/gensec/internal/llm"
	"github.com/shivansh-source/gensec/internal/scanner"
)

func main() {
	_ = godotenv.Load()

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "scan":
		cmdScan()
	case "fix":
		cmdFix()
	case "status":
		cmdStatus()
	case "pr":
		cmdCreatePR()
	case "scan-and-fix":
		cmdScanAndFix()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
	}
}

func cmdScan() {
	fmt.Println("\n🚀 GenSec Pro v3 - Data Flow Flagging Scanner")
	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Printf("Plan: %s\n", config.UserPlan)

	// Validate credentials — re-read from env so .env loaded by godotenv is respected
	groqKey := os.Getenv("GROQ_API_KEY")
	if groqKey == "" {
		groqKey = config.GroqAPIKey // fallback to package-level var (set at init)
	}
	if groqKey == "" {
		fmt.Println("Missing GROQ_API_KEY")
		return
	}

	// Decide scan root: default ".", or use arg if provided
	scanRoot := "."
	if len(os.Args) >= 3 && os.Args[2] != "" {
		scanRoot = os.Args[2]
	}
	fmt.Printf("📂 Scan root: %s\n", scanRoot)

	// Load file content
	fileContent := loadFileContent(scanRoot)
	if len(fileContent) == 0 {
		fmt.Println("⚠️  No .go files found")
		return
	}

	fmt.Printf("📁 Loaded %d files\n", len(fileContent))

	// Phase 1: Multi-Scanner
	multiScanner := scanner.NewMultiScanner(config.UserPlan, scanRoot)
	findings, err := multiScanner.ScanAll()
	if err != nil {
		fmt.Printf("❌ Scanning failed: %v\n", err)
		return
	}

	if len(findings) == 0 {
		fmt.Println("\n🎉 No vulnerabilities found!")
		return
	}

	// Phase 2: Data Flow Flagging
	flagEngine := flagging.NewFlagEngine()
	flags, err := flagEngine.ProcessFindings(findings, fileContent)
	if err != nil {
		fmt.Printf("❌ Flagging failed: %v\n", err)
		return
	}

	// Phase 3: LLM Triage
	triager := llm.NewLLMTriager()
	triaged, err := triager.TriageFlags(flags)
	if err != nil {
		fmt.Printf("⚠️  LLM triage failed: %v (using unfiltered flags)\n", err)
		triaged = flags
	}

	// Report
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ SCAN COMPLETE")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\nTotal findings (all scanners): %d\n", len(findings))
	fmt.Printf("After data-flow flagging: %d\n", len(flags))
	fmt.Printf("After LLM triage (confidence >= 60%%): %d\n", len(triaged))
	fmt.Printf("\nResults saved to:\n")
	fmt.Printf("  - %s (all flags)\n", config.ReportFileFlagged)
	fmt.Printf("\n✅ Ready for PHASE 4: Batch Fix & Verify\n")
}

func cmdFix() {
	fmt.Println("\n🔧 GenSec Pro v3 - Batch Fixer")
	fmt.Println("=" + strings.Repeat("=", 59))

	// Load flagged findings from previous scan
	data, err := os.ReadFile(config.ReportFileFlagged)
	if err != nil {
		fmt.Println("❌ No flagged findings found. Run 'scan' first.")
		return
	}

	var flags []flagging.Flag
	if err := json.Unmarshal(data, &flags); err != nil {
		fmt.Printf("❌ Failed to parse flags: %v\n", err)
		return
	}

	if len(flags) == 0 {
		fmt.Println("✅ No flags to fix!")
		return
	}

	// Group flags by file
	flagsByFile := make(map[string][]flagging.Flag)
	for _, flag := range flags {
		flagsByFile[flag.File] = append(flagsByFile[flag.File], flag)
	}

	fmt.Printf("\n📋 Found %d files with flagged vulnerabilities\n", len(flagsByFile))

	// Batch fix
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PHASE 4: BATCH FIX & VERIFICATION (LOOP)")
	fmt.Println(strings.Repeat("=", 60))

	batchFixer := fixer.NewBatchFixer()
	prCount := 0

	type fileSummary struct {
		file      string
		fixed     int
		failed    int
		escalated int
		prDesc    string
	}

	var summaries []fileSummary

	for file, fileFlags := range flagsByFile {
		if prCount >= config.MaxPRsPerRun {
			fmt.Printf("\n⚠️  Reached PR limit (%d)\n", config.MaxPRsPerRun)
			break
		}

		// Resolve a concrete path and read current file content from disk
		path := filepath.ToSlash(filepath.Clean(file))
		if !filepath.IsAbs(path) {
			// relative to current working dir (inside container: /scan)
			path = filepath.Clean(path)
		}

		src, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("⚠️  Failed to read file %s: %v\n", path, err)
			continue
		}
		content := string(src)

		// Call batch fixer on this file
		result := batchFixer.FixFileVulnerabilities(path, fileFlags, content)

		if result.Status != "failed" && result.FixedCode != "" {
			// Save fixed code back to the same file (in /scan → host project)
			if err := os.WriteFile(path, []byte(result.FixedCode), 0644); err != nil {
				fmt.Printf("❌ Failed to save fixed file: %v\n", err)
				continue
			}

			fmt.Printf("\n✅ Fixed file saved: %s\n", path)
			prCount++

			summaries = append(summaries, fileSummary{
				file:      file,
				fixed:     len(result.VulnsFixed),
				failed:    len(result.VulnsFailed),
				escalated: len(result.VulnsEscalated),
				prDesc:    result.PRDescription,
			})
		}

		// Print per-file PR description (for reference)
		fmt.Printf("\n📝 PR Description:\n")
		fmt.Println(result.PRDescription)
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ BATCH FIX COMPLETE")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\nFiles fixed: %d\n", prCount)
	for _, r := range summaries {
		fmt.Printf("  - %s: %d fixed, %d failed, %d escalated\n", r.file, r.fixed, r.failed, r.escalated)
	}
	fmt.Printf("\n📝 Attempt tracking: %s\n", config.AttemptLogFile)

	// 👉 Build combined PR body for the next `gensec pr` call
	if len(summaries) > 0 {
		var b strings.Builder
		b.WriteString("## GenSec: Automated Security Fixes\n\n")
		b.WriteString("This pull request was generated automatically by GenSec after scanning and fixing vulnerabilities.\n\n")

		b.WriteString("### Files Processed\n")
		for _, s := range summaries {
			b.WriteString(fmt.Sprintf("- `%s`: %d fixed, %d failed, %d escalated\n", s.file, s.fixed, s.failed, s.escalated))
		}
		b.WriteString("\n")

		b.WriteString("### Detailed Fix Report\n\n")
		for _, s := range summaries {
			b.WriteString(s.prDesc)
			b.WriteString("\n\n---\n\n")
		}

		b.WriteString("> Generated by GenSec Autonomous Security Agent.\n")

		if err := os.WriteFile("gensec_pr_body.md", []byte(b.String()), 0644); err != nil {
			fmt.Printf("⚠️  Failed to write gensec_pr_body.md: %v\n", err)
		} else {
			fmt.Println("\n📝 PR body written to gensec_pr_body.md (will be used by `gensec pr`)")
		}
	}
}

func cmdStatus() {
	fmt.Println("📊 GenSec Status")
	fmt.Printf("Plan: %s\n", config.UserPlan)
	fmt.Printf("GitHub User: %s\n", config.GitHubUser)

	if _, err := os.Stat(config.ReportFileFlagged); err == nil {
		data, _ := os.ReadFile(config.ReportFileFlagged)
		var flags []flagging.Flag
		_ = json.Unmarshal(data, &flags)
		fmt.Printf("Flagged findings: %d\n", len(flags))
	}
}

func loadFileContent(root string) map[string]string {
	content := make(map[string]string)

	cwd, _ := os.Getwd()
	fmt.Printf("🔍 Walking files from root=%s (cwd=%s)\n", root, cwd)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") ||
				info.Name() == "vendor" ||
				info.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Load .go files
		if strings.HasSuffix(path, ".go") {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			// Normalize keys so we can match scanner output formats
			abs := filepath.Clean(path)

			rel, errRel := filepath.Rel(root, path)
			if errRel != nil {
				rel = filepath.Base(path)
			}
			rel = filepath.ToSlash(rel)

			base := filepath.Base(path)

			// Store all lookup forms
			content[rel] = string(data)  // ex: vulnerable.go or src/vulnerable.go
			content[base] = string(data) // vulnerable.go
			content[abs] = string(data)  // /scan/vulnerable.go

			return nil
		}

		return nil
	})

	if err != nil {
		fmt.Printf("⚠️  Error loading files: %v\n", err)
	}

	return content
}

func cmdCreatePR() {
	fmt.Println("\n📦 GenSec - Create GitHub PR from current changes")
	fmt.Println("=" + strings.Repeat("=", 59))

	client, err := gh.NewClientFromEnv()
	if err != nil {
		fmt.Printf("❌ GitHub client error: %v\n", err)
		return
	}

	baseBranch := os.Getenv("GITHUB_BASE_BRANCH")
	if baseBranch == "" {
		baseBranch = "main"
	}

	prTitle := "GenSec: Automated security fixes"

	// Default PR body (fallback)
	prBody := "This pull request contains automated security fixes generated by GenSec.\n\n" +
		"Please review the changes and merge if they look good."

	// 👉 Prefer gensec_pr_body.md if it exists
	if data, err := os.ReadFile("gensec_pr_body.md"); err == nil && len(data) > 0 {
		prBody = string(data)
		fmt.Println("📝 Using PR body from gensec_pr_body.md")
	}

	prURL, err := client.CreatePRForCurrentChanges(baseBranch, prTitle, prBody)
	if err != nil {
		fmt.Printf("❌ Failed to create PR: %v\n", err)
		return
	}

	fmt.Println("\n✅ Pull Request created successfully!")
	fmt.Printf("🔗 %s\n", prURL)
}

func cmdScanAndFix() {
	fmt.Println("\n🌀 GenSec Pro v3 - Scan → Fix → PR")
	fmt.Println("=" + strings.Repeat("=", 59))

	// Optional path argument, like: gensec scan-and-fix /scan
	scanRoot := "."
	if len(os.Args) >= 3 {
		scanRoot = os.Args[2]
	}

	// 1) Run scan (Phase 1–3)
	fmt.Println("\n🔍 STEP 1/3: Scanning for vulnerabilities...")
	// cmdScan reads os.Args[2] as path, so this just works:
	// os.Args is still ["gensec", "scan-and-fix", "/scan"]
	// and cmdScan already handles that.
	os.Args = []string{os.Args[0], "scan", scanRoot}
	cmdScan()

	// 2) Run fixer (Phase 4)
	fmt.Println("\n🛠 STEP 2/3: Fixing vulnerabilities...")
	os.Args = []string{os.Args[0], "fix"}
	cmdFix()

	// 3) Create PR (Phase 5)
	fmt.Println("\n📦 STEP 3/3: Creating GitHub PR...")
	os.Args = []string{os.Args[0], "pr"}
	cmdCreatePR()
}

func printUsage() {
	fmt.Print(`
🤖 GenSec Pro v3 - Autonomous Vulnerability Fixer with Data Flow Flagging

Usage:
  gensec scan [path]                       # Scan, flag, and triage vulns
  gensec fix                               # Batch fix vulnerabilities
  gensec status                            # Show scan status
  gensec pr                                # Create a GitHub PR from current changes
  gensec scan-and-fix [path]               # 🔁 Scan → Fix → PR in one go   <-- NEW

Environment Variables:
  GROQ_API_KEY                             # Groq API key (required for scan/fix)
  GITHUB_TOKEN                             # GitHub PAT (required for PR)
  GITHUB_USER                              # GitHub username
  GITHUB_REPO                              # "owner/repo" (e.g., shivansh-source/my-repo)
  USER_PLAN                                # "free", "pro", "enterprise"

Example:
  export GROQ_API_KEY=gsk_...
  export USER_PLAN=pro
  export GITHUB_TOKEN=ghp_...
  export GITHUB_USER=shivansh-source
  export GITHUB_REPO=shivansh-source/my-repo

  gensec scan-and-fix /scan
`)
}
