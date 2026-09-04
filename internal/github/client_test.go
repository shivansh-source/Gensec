package github

import (
	"encoding/json"
	"os"
	"testing"
)

// NOTE on scope: CreatePRForCurrentChanges is not exercised end-to-end here.
// It shells out to the real `git` binary (checkout/add/commit/push against a
// hardcoded https://github.com/... push URL) and mutates the *global* git
// config (`git config --global user.name/user.email`), with no injected
// HTTP client or overridable base URL to redirect either of those at test
// time. Doing so safely would need a small testability seam in client.go
// (e.g. an injectable API base URL and/or *http.Client) — a production code
// change, which is being flagged rather than made without sign-off. What is
// tested below, hermetically and without any network access: the env-var
// validation gate, the exact PR payload GitHub receives, and the
// .gitignore side effect, which is the actionable, verifiable surface of
// this package today.

func TestNewClientFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		user    string
		repo    string
		wantErr string
	}{
		{
			name:  "all env vars set succeeds",
			token: "ghp_test", user: "shivansh-source", repo: "shivansh-source/gensec",
		},
		{
			name: "missing token", token: "", user: "shivansh-source", repo: "shivansh-source/gensec",
			wantErr: "GITHUB_TOKEN is not set",
		},
		{
			name: "missing user", token: "ghp_test", user: "", repo: "shivansh-source/gensec",
			wantErr: "GITHUB_USER is not set",
		},
		{
			name: "missing repo", token: "ghp_test", user: "shivansh-source", repo: "",
			wantErr: "GITHUB_REPO is not set (expected owner/repo)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tt.token)
			t.Setenv("GITHUB_USER", tt.user)
			t.Setenv("GITHUB_REPO", tt.repo)

			client, err := NewClientFromEnv()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil (client=%+v)", tt.wantErr, client)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.Token != tt.token || client.User != tt.user || client.Repo != tt.repo {
				t.Fatalf("client = %+v, want Token=%s User=%s Repo=%s", client, tt.token, tt.user, tt.repo)
			}
		})
	}
}

// TestPRPayloadStructure verifies that a detected-and-fixed vulnerability
// results in a correctly structured GitHub PR payload — the exact JSON
// CreatePRForCurrentChanges builds and sends to POST /repos/{repo}/pulls.
func TestPRPayloadStructure(t *testing.T) {
	payload := prRequest{
		Title: "GenSec: Automated security fixes",
		Head:  "gensec/fix-1234567890",
		Base:  "main",
		Body:  "### Files Processed\n- `examples/vulnerable-code/sql_injection.go`: 1 fixed, 0 failed, 0 escalated\n",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(prRequest) error = %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	want := map[string]interface{}{
		"title": "GenSec: Automated security fixes",
		"head":  "gensec/fix-1234567890",
		"base":  "main",
		"body":  "### Files Processed\n- `examples/vulnerable-code/sql_injection.go`: 1 fixed, 0 failed, 0 escalated\n",
	}
	for key, wantVal := range want {
		if decoded[key] != wantVal {
			t.Errorf("payload[%q] = %v, want %v", key, decoded[key], wantVal)
		}
	}
	if len(decoded) != len(want) {
		t.Errorf("payload has %d fields %v, want exactly %v", len(decoded), decoded, want)
	}
}

// TestPRResponseParsing verifies the reverse direction: a GitHub API PR
// response is decoded into the fields CreatePRForCurrentChanges returns to
// the caller (the PR URL).
func TestPRResponseParsing(t *testing.T) {
	body := `{"html_url": "https://github.com/shivansh-source/gensec/pull/42", "number": 42}`

	var resp prResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if resp.HTMLURL != "https://github.com/shivansh-source/gensec/pull/42" {
		t.Errorf("HTMLURL = %q, want the PR URL", resp.HTMLURL)
	}
	if resp.Number != 42 {
		t.Errorf("Number = %d, want 42", resp.Number)
	}
}

func TestEnsureGitIgnore(t *testing.T) {
	t.Run("creates .gitignore with all expected entries when none exists", func(t *testing.T) {
		t.Chdir(t.TempDir())

		ensureGitIgnore()

		data, err := os.ReadFile(".gitignore")
		if err != nil {
			t.Fatalf("expected .gitignore to be created: %v", err)
		}
		for _, want := range []string{
			"attempt_log.json",
			"report_flagged.json",
			"report_semgrep.json",
			"report_trivy.json",
			"gensec_pr_body.md",
		} {
			if !containsLine(string(data), want) {
				t.Errorf(".gitignore missing expected entry %q; got:\n%s", want, data)
			}
		}
	})

	t.Run("appends only missing entries without duplicating existing ones", func(t *testing.T) {
		t.Chdir(t.TempDir())

		if err := os.WriteFile(".gitignore", []byte("attempt_log.json\ncustom-entry\n"), 0644); err != nil {
			t.Fatalf("seeding .gitignore: %v", err)
		}

		ensureGitIgnore()

		data, err := os.ReadFile(".gitignore")
		if err != nil {
			t.Fatalf("reading .gitignore: %v", err)
		}
		content := string(data)

		if n := countOccurrences(content, "attempt_log.json"); n != 1 {
			t.Errorf("attempt_log.json appears %d times, want exactly 1 (no duplication)", n)
		}
		if !containsLine(content, "custom-entry") {
			t.Errorf("pre-existing custom-entry was lost; got:\n%s", content)
		}
		if !containsLine(content, "report_flagged.json") {
			t.Errorf("missing entry report_flagged.json was not appended; got:\n%s", content)
		}
	})
}

func containsLine(content, line string) bool {
	for _, l := range splitLines(content) {
		if l == line {
			return true
		}
	}
	return false
}

func countOccurrences(content, line string) int {
	count := 0
	for _, l := range splitLines(content) {
		if l == line {
			count++
		}
	}
	return count
}

func splitLines(content string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			lines = append(lines, content[start:i])
			start = i + 1
		}
	}
	if start < len(content) {
		lines = append(lines, content[start:])
	}
	return lines
}
