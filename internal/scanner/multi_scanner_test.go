package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeFile writes content to name inside dir, creating parent directories
// as needed, and fails the test on error.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// vulnIDs extracts and sorts the VulnID of every finding, so assertions
// don't depend on filepath.Walk's traversal order.
func vulnIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.VulnID)
	}
	sort.Strings(ids)
	return ids
}

// TestRunGenSecPatterns covers the in-process regex/substring detector that
// decides whether a line of Go source becomes a Finding. Each case is run in
// its own temp directory so files can't cross-contaminate results.
func TestRunGenSecPatterns(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantIDs []string
	}{
		{
			name: "clean code produces no findings",
			code: `package main

func Add(a, b int) int {
	return a + b
}
`,
			wantIDs: nil,
		},
		{
			name: "SQL injection via string concatenation",
			code: `package main

func Query(db *sql.DB, id string) {
	query := "SELECT * FROM users WHERE id = " + id
	db.Exec(query)
}
`,
			wantIDs: []string{"gensec.sqli.string-concat"},
		},
		{
			name: "SQL injection via fmt.Sprintf",
			code: `package main

func Query(db *sql.DB, id string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Exec(query)
}
`,
			wantIDs: []string{"gensec.sqli.sprintf"},
		},
		{
			name: "unparameterized db.Query call",
			code: `package main

func Query(db *sql.DB, query string) {
	rows, err := db.Query(query)
	_ = rows
	_ = err
}
`,
			wantIDs: []string{"gensec.sqli.unparameterized-query"},
		},
		{
			name: "parameterized db.Query call is not flagged",
			code: `package main

func Query(db *sql.DB, query, id string) {
	rows, err := db.Query(query, id)
	_ = rows
	_ = err
}
`,
			wantIDs: nil,
		},
		{
			name: "command injection via shell exec",
			code: `package main

func Run(userInput string) {
	cmd := exec.Command("sh", "-c", userInput)
	cmd.Run()
}
`,
			wantIDs: []string{"gensec.command-injection.exec-command"},
		},
		{
			name: "path traversal via concatenated path",
			code: `package main

func Download(filename string) {
	filePath := "/uploads/" + filename
	_ = filePath
}
`,
			wantIDs: []string{"gensec.path-traversal.user-path"},
		},
		{
			name: "path traversal via ReadFile on user path",
			code: `package main

func Download(filePath string) {
	data, _ := ioutil.ReadFile(filePath)
	_ = data
}
`,
			wantIDs: []string{"gensec.path-traversal.file-read"},
		},
		{
			name: "unrestricted file upload via FormFile",
			code: `package main

func Upload(r *http.Request) {
	file, _, _ := r.FormFile("file")
	_ = file
}
`,
			wantIDs: []string{"gensec.file-upload.unrestricted"},
		},
		{
			name: "unrestricted upload write also trips path-traversal heuristic",
			code: `package main

func Save(filename string, data []byte) {
	os.WriteFile("/uploads/" + filename, data, 0644)
}
`,
			// The write-path and the "/uploads/" + concat heuristics are
			// independent checks, so a single line can legitimately match
			// both. This is intentional current behavior, not a bug — the
			// test pins it down so a future change is a deliberate decision.
			wantIDs: []string{"gensec.file-upload.write-unsafe-path", "gensec.path-traversal.user-path"},
		},
		{
			name: "PostFormValue without csrf reference is flagged",
			code: `package main

func Handle(r *http.Request) {
	email := r.PostFormValue("email")
	_ = email
}
`,
			wantIDs: []string{"gensec.csrf.missing-token"},
		},
		{
			name: "PostFormValue mentioning csrf is not flagged",
			code: `package main

func Handle(r *http.Request) {
	token := r.PostFormValue("csrf_token")
	_ = token
}
`,
			wantIDs: nil,
		},
		{
			name: "unbounded loop DoS heuristic",
			code: `package main

func Loop(num int) {
	for i := 0; i < num; i++ {
		_ = i
	}
}
`,
			wantIDs: []string{"gensec.dos.unbounded-loop"},
		},
		{
			name: "hardcoded AWS-style secret",
			code: `package main

const key = "AKIAABCDEFGHIJKLMNOP"
`,
			wantIDs: []string{"gensec.hardcoded-secret.literal"},
		},
		{
			name: "hardcoded-secret heuristic false-positives on unrelated 'sk-' substring",
			code: `package main

// risk-based prioritization, revisit later
func Prioritize() {}
`,
			// "risk-based" contains the literal substring "sk-", which is
			// one of the hardcoded-secret markers. This is a known noisy
			// heuristic (see repo audit) — pinned here so it's a visible,
			// deliberate fact rather than a surprise.
			wantIDs: []string{"gensec.hardcoded-secret.literal"},
		},
		{
			name: "sensitive data logged via fmt.Println",
			code: `package main

func Debug(password string) {
	fmt.Println("using password:", password)
}
`,
			wantIDs: []string{"gensec.logging.sensitive-data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "case.go", tt.code)

			m := NewMultiScanner("free", dir)
			findings, err := m.runGenSecPatterns()
			if err != nil {
				t.Fatalf("runGenSecPatterns() error = %v", err)
			}

			got := vulnIDs(findings)
			want := append([]string(nil), tt.wantIDs...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("VulnIDs = %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("VulnIDs = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestRunGenSecPatterns_DotAsScanRoot is a regression test: filepath.Walk
// reports the walk root itself with Name() == "." when the root is exactly
// ".", which used to match the hidden-directory skip and discard the
// entire tree before visiting a single file - meaning a scan root of "."
// (the default for a bare `gensec scan`) always reported zero findings.
func TestRunGenSecPatterns_DotAsScanRoot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "case.go", `package main

func Query(db *sql.DB, id string) {
	query := "SELECT * FROM users WHERE id = " + id
	db.Exec(query)
}
`)

	t.Chdir(dir)

	m := NewMultiScanner("free", ".")
	findings, err := m.runGenSecPatterns()
	if err != nil {
		t.Fatalf("runGenSecPatterns() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("scanning \".\" found %d findings, want 1 (got: %v)", len(findings), vulnIDs(findings))
	}
}

func TestRunGenSecPatterns_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	m := NewMultiScanner("free", dir)
	findings, err := m.runGenSecPatterns()
	if err != nil {
		t.Fatalf("runGenSecPatterns() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings in an empty directory, got %d", len(findings))
	}
}

func TestRunGenSecPatterns_SkipsIgnoredDirsAndNonGoFiles(t *testing.T) {
	dir := t.TempDir()

	vulnerable := `package main

func Query(db *sql.DB, id string) {
	query := "SELECT * FROM users WHERE id = " + id
	db.Exec(query)
}
`
	// Should be skipped: vendor/, .git/, and non-.go files.
	writeFile(t, dir, filepath.Join("vendor", "pkg", "vuln.go"), vulnerable)
	writeFile(t, dir, filepath.Join(".git", "vuln.go"), vulnerable)
	writeFile(t, dir, "notes.txt", vulnerable)

	// Should be scanned.
	writeFile(t, dir, filepath.Join("real", "vuln.go"), vulnerable)

	m := NewMultiScanner("free", dir)
	findings, err := m.runGenSecPatterns()
	if err != nil {
		t.Fatalf("runGenSecPatterns() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (from real/vuln.go only), got %d: %+v", len(findings), findings)
	}
	if got := filepath.ToSlash(findings[0].File); filepath.Base(got) != "vuln.go" || filepath.Base(filepath.Dir(got)) != "real" {
		t.Fatalf("expected finding from real/vuln.go, got %s", findings[0].File)
	}
}

func TestDeduplicate(t *testing.T) {
	m := &MultiScanner{}

	t.Run("identical File:Line:CWE keys collapse to the first occurrence", func(t *testing.T) {
		findings := []Finding{
			{Tool: "semgrep", File: "a.go", Line: 10, CWE: "CWE-89", VulnID: "first"},
			{Tool: "gensec-patterns", File: "a.go", Line: 10, CWE: "CWE-89", VulnID: "second"},
			{Tool: "semgrep", File: "b.go", Line: 10, CWE: "CWE-89", VulnID: "third"},
		}

		got := m.deduplicate(findings)
		if len(got) != 2 {
			t.Fatalf("expected 2 findings after dedup, got %d: %+v", len(got), got)
		}
		if got[0].VulnID != "first" {
			t.Fatalf("expected the first-seen finding to survive, got VulnID=%s", got[0].VulnID)
		}
	})

	t.Run("known limitation: same-file Trivy findings collapse because Line and CWE are always identical", func(t *testing.T) {
		// Every Trivy finding is built with Line: 0 and CWE: "CWE-Unknown"
		// (see runTrivy), so two distinct CVEs on the same file produce the
		// same dedup key and only the first survives. This is a real gap,
		// not intended coverage — pinned here so it's visible and any fix
		// is a deliberate change, not an accidental behavior shift.
		findings := []Finding{
			{Tool: "trivy", File: "go.sum", Line: 0, CWE: "CWE-Unknown", VulnID: "CVE-2024-0001"},
			{Tool: "trivy", File: "go.sum", Line: 0, CWE: "CWE-Unknown", VulnID: "CVE-2024-0002"},
		}

		got := m.deduplicate(findings)
		if len(got) != 1 {
			t.Fatalf("expected the known dedup collision to drop one finding, got %d survive: %+v", len(got), got)
		}
	})
}

func TestExtractCWE(t *testing.T) {
	m := &MultiScanner{}

	tests := []struct {
		name    string
		checkID string
		want    string
	}{
		{"dotted id ending in a known gosec code", "go.lang.security.audit.G201", "CWE-89"},
		{"bare known gosec code with no dot", "G204", "CWE-78"},
		{"dotted id with no matching suffix falls through", "go.lang.security.audit.sql-injection", "CWE-Unknown"},
		{"empty string", "", "CWE-Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.extractCWE(tt.checkID); got != tt.want {
				t.Errorf("extractCWE(%q) = %q, want %q", tt.checkID, got, tt.want)
			}
		})
	}
}
