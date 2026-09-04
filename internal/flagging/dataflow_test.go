package flagging

import (
	"strings"
	"testing"
)

// TestAnalyzeFinding_Stages walks the three possible outcomes of
// AnalyzeFinding: no source found, source found but no sink, and a full
// source-to-sink match. This is the code path that decides whether a raw
// scanner finding is actually "actionable" — its Type and Confidence drive
// the later LLM-triage filtering.
func TestAnalyzeFinding_Stages(t *testing.T) {
	analyzer := NewDataFlowAnalyzer()

	t.Run("no source detected on the flagged line", func(t *testing.T) {
		content := lines(
			"package main",
			"",
			"func Handler() {",
			"	x := 5",
			"	y := x + 1",
			"	fmt.Println(y)",
			"	return",
			"}",
		)
		// Line 4 has no source/sink pattern at all.
		flag := analyzer.AnalyzeFinding("h.go", 4, "CWE-89", "HIGH", "msg", "x := 5", content)

		if flag.Type != "RISKY_PATTERN" {
			t.Errorf("Type = %q, want RISKY_PATTERN", flag.Type)
		}
		if flag.Confidence != 0.5 {
			t.Errorf("Confidence = %v, want 0.5", flag.Confidence)
		}
	})

	t.Run("source detected but no sink on the same line", func(t *testing.T) {
		// Source and sink detection both look at the exact same single
		// line within the ±5-line context window — they do not scan the
		// whole window. A source with no sink alongside it on that one
		// line stops at SOURCE_DETECTED, even if a sink exists elsewhere
		// in the surrounding context. Line 7 is used (rather than <=6) to
		// stay outside getCodeContext's clamping zone so this test isn't
		// itself tripped up by the line-index bug covered separately
		// below, and os.Getenv is used as the source (rather than the
		// URL_PARAM pattern) because URL_PARAM's own text contains
		// "Query(", which would coincidentally also match the generic
		// SQL_QUERY sink regex on the very same line.
		content := lines(
			"package main",
			"",
			"func Handler() {",
			"	// padding so the finding line sits past index 6",
			"	// padding",
			"	// padding",
			"	apiKey := os.Getenv(\"API_KEY\")",
			"	fmt.Println(\"done\")",
			"}",
		)
		flag := analyzer.AnalyzeFinding("h.go", 7, "CWE-798", "HIGH", "msg", "apiKey := os.Getenv(\"API_KEY\")", content)

		if flag.Type != "SOURCE_DETECTED" {
			t.Fatalf("Type = %q, want SOURCE_DETECTED", flag.Type)
		}
		if flag.SourceType != "ENV_VAR" {
			t.Errorf("SourceType = %q, want ENV_VAR", flag.SourceType)
		}
		if flag.Confidence != 0.4 {
			t.Errorf("Confidence = %v, want 0.4", flag.Confidence)
		}
	})

	t.Run("source and sink on the same line is a full match", func(t *testing.T) {
		content := lines(
			"package main",
			"",
			"func Handler(w http.ResponseWriter, r *http.Request) {",
			"	// padding so the finding line sits past index 6",
			"	// padding",
			"	// padding",
			"	rows := db.Query(r.URL.Query().Get(\"id\"))",
			"	_ = rows",
			"}",
		)
		flag := analyzer.AnalyzeFinding("h.go", 7, "CWE-89", "CRITICAL", "msg", "snippet", content)

		if flag.Type != "SOURCE_TO_SINK" {
			t.Fatalf("Type = %q, want SOURCE_TO_SINK", flag.Type)
		}
		if flag.SourceType != "URL_PARAM" || flag.SinkType != "SQL_QUERY" {
			t.Errorf("SourceType/SinkType = %q/%q, want URL_PARAM/SQL_QUERY", flag.SourceType, flag.SinkType)
		}
		if flag.IsSanitized {
			t.Errorf("IsSanitized = true, want false (no sanitizer call present)")
		}
	})

	t.Run("known bug: findings on or before line 6 can be analyzed against the wrong line", func(t *testing.T) {
		// getCodeContext clamps its window start to 0 for any line <= 6,
		// but DetectSource/DetectSink always look at hardcoded context
		// index 6 ("the middle"). For line <= 6 that index no longer lines
		// up with the actual flagged line, so a real vulnerability near
		// the top of a file can be silently missed. This test pins down
		// that current (buggy) behavior — see repo audit — rather than
		// silently "fixing" it here.
		content := lines(
			"package main",
			"	db.Query(r.URL.Query().Get(\"id\"))", // line 2: the actual vulnerable line
			"func H(r *http.Request) {",
			"	// padding",
			"	// padding",
			"	// padding, no source/sink pattern here", // line 6: what gets analyzed instead
			"	// padding",
			"}",
		)

		flag := analyzer.AnalyzeFinding("h.go", 2, "CWE-89", "CRITICAL", "msg", "snippet", content)

		// Because of the clamping bug, the analyzer reads line 6 (a plain
		// comment) instead of line 2 (the real source+sink line), so it
		// fails to find a source at all.
		if flag.Type != "RISKY_PATTERN" {
			t.Fatalf("expected the clamping bug to misread the line and yield RISKY_PATTERN, got %q (SourceType=%q) — if this now passes, the line-index bug may have been fixed and this test should be updated", flag.Type, flag.SourceType)
		}
	})
}

func TestCalculateConfidence(t *testing.T) {
	a := &DataFlowAnalyzer{}

	tests := []struct {
		name        string
		sourceType  string
		sinkType    string
		isSanitized bool
		severity    string
		want        float64
	}{
		{"critical, source+sink, not sanitized", "URL_PARAM", "SQL_QUERY", false, "CRITICAL", 0.95*0.8 + 0.2},
		{"critical, source+sink, sanitized", "URL_PARAM", "SQL_QUERY", true, "CRITICAL", (0.95*0.3)*0.8 + 0.2},
		{"high, no source/sink recorded, not sanitized", "", "", false, "HIGH", 0.85},
		{"unknown severity defaults to 0.5 base", "URL_PARAM", "SQL_QUERY", false, "WHATEVER", 0.5*0.8 + 0.2},
		{"low, sanitized, source+sink", "URL_PARAM", "SQL_QUERY", true, "LOW", (0.50*0.3)*0.8 + 0.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.calculateConfidence(tt.sourceType, tt.sinkType, tt.isSanitized, tt.severity)
			if diff := got - tt.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("calculateConfidence(%q,%q,%v,%q) = %v, want %v", tt.sourceType, tt.sinkType, tt.isSanitized, tt.severity, got, tt.want)
			}
		})
	}
}

// lines joins its arguments with "\n" to build fixture file content, purely
// so test cases below read as a list of source lines instead of one long
// escaped string.
func lines(ls ...string) string {
	return strings.Join(ls, "\n")
}
