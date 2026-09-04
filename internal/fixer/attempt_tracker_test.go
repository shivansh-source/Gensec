package fixer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shivansh-source/gensec/internal/config"
)

// newTestTracker builds an AttemptTracker backed by a throwaway file instead
// of the real attempt_log.json, so tests never touch repo state.
func newTestTracker(t *testing.T) *AttemptTracker {
	t.Helper()
	return &AttemptTracker{
		logs: make(map[string]*AttemptLog),
		file: filepath.Join(t.TempDir(), "attempt_log.json"),
	}
}

func TestRecordAttempt_IncrementsAndPersists(t *testing.T) {
	at := newTestTracker(t)

	at.RecordAttempt("gensec.sqli.string-concat", "failed", "syntax error")
	at.RecordAttempt("gensec.sqli.string-concat", "fixed", "")

	if got := at.GetAttempts("gensec.sqli.string-concat"); got != 2 {
		t.Fatalf("GetAttempts = %d, want 2", got)
	}

	// A fresh tracker pointed at the same file should reload the same state.
	reloaded := &AttemptTracker{logs: make(map[string]*AttemptLog), file: at.file}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := reloaded.GetAttempts("gensec.sqli.string-concat"); got != 2 {
		t.Fatalf("after reload, GetAttempts = %d, want 2", got)
	}
	if got := reloaded.logs["gensec.sqli.string-concat"].Status; got != "fixed" {
		t.Fatalf("after reload, Status = %q, want %q (last recorded status)", got, "fixed")
	}
}

func TestGetAttempts_UnknownVulnIsZero(t *testing.T) {
	at := newTestTracker(t)
	if got := at.GetAttempts("never-seen"); got != 0 {
		t.Fatalf("GetAttempts(unknown) = %d, want 0", got)
	}
}

func TestShouldRetry_Threshold(t *testing.T) {
	at := newTestTracker(t)
	const vulnID = "gensec.hardcoded-secret.literal"

	for i := 0; i < config.MaxAttemptsPerVuln; i++ {
		if !at.ShouldRetry(vulnID) {
			t.Fatalf("ShouldRetry should be true before attempt %d (max is %d)", i+1, config.MaxAttemptsPerVuln)
		}
		at.RecordAttempt(vulnID, "failed", "still failing")
	}

	if at.ShouldRetry(vulnID) {
		t.Fatalf("ShouldRetry should be false once attempts (%d) reach MaxAttemptsPerVuln (%d)",
			at.GetAttempts(vulnID), config.MaxAttemptsPerVuln)
	}
}

func TestMarkEscalated(t *testing.T) {
	at := newTestTracker(t)
	const vulnID = "gensec.sqli.unparameterized-query"

	at.RecordAttempt(vulnID, "failed", "still vulnerable")
	at.MarkEscalated(vulnID)

	if got := at.logs[vulnID].Status; got != "escalated" {
		t.Fatalf("Status = %q, want escalated", got)
	}

	// Persisted, not just in-memory.
	reloaded := &AttemptTracker{logs: make(map[string]*AttemptLog), file: at.file}
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := reloaded.logs[vulnID].Status; got != "escalated" {
		t.Fatalf("after reload, Status = %q, want escalated", got)
	}
}

func TestLoad_MissingFileIsNotAnError(t *testing.T) {
	at := &AttemptTracker{
		logs: make(map[string]*AttemptLog),
		file: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}

	if err := at.Load(); err != nil {
		t.Fatalf("Load() on a missing file should return nil, got %v", err)
	}
	if len(at.logs) != 0 {
		t.Fatalf("expected no logs loaded, got %d", len(at.logs))
	}
}

func TestLoad_MalformedJSONReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempt_log.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("seeding malformed file: %v", err)
	}

	at := &AttemptTracker{logs: make(map[string]*AttemptLog), file: path}
	if err := at.Load(); err == nil {
		t.Fatal("Load() on malformed JSON should return an error, got nil")
	}
}
