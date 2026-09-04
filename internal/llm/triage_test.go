package llm

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/shivansh-source/gensec/internal/flagging"
)

// TestBuildPrompt_IsStable pins the exact prompt template sent to the LLM.
// If someone edits the wording, fields, or JSON-output instructions in
// buildPrompt, this test breaks — which is the point: the prompt is a
// contract with the model, and an accidental change here should never be
// silent.
func TestBuildPrompt_IsStable(t *testing.T) {
	lt := &LLMTriager{}
	flag := flagging.Flag{
		CWE:         "CWE-89",
		Severity:    "CRITICAL",
		Message:     "SQL query built by string concatenation with user input; possible SQL injection.",
		SourceType:  "URL_PARAM",
		Source:      "id",
		SinkType:    "SQL_QUERY",
		Sink:        "db.Query",
		IsSanitized: false,
		Confidence:  0.75,
		CodeContext: "  10: id := r.URL.Query().Get(\"id\")\n→  11: db.Query(query, id)\n",
	}

	want := fmt.Sprintf(`You are a Go security expert analyzing a potential vulnerability.

**Finding:**
- CWE: %s
- Severity: %s
- Message: %s

**Data Flow Analysis:**
- Source Type: %s (Variable: %s)
- Sink Type: %s (Operation: %s)
- Sanitized: %v
- Current Confidence: %.2f

**Code Context:**
%s

**Your Task:**
1. Is this a REAL vulnerability or FALSE POSITIVE?
2. What is your CONFIDENCE? (0.0-1.0)
3. Brief explanation (1-2 sentences)

**Output JSON (ONLY JSON, NO OTHER TEXT):**
{
    "is_real": true,
    "confidence": 0.85,
    "explanation": "Your explanation here"
}
`, flag.CWE, flag.Severity, flag.Message, flag.SourceType, flag.Source, flag.SinkType, flag.Sink, flag.IsSanitized, flag.Confidence, flag.CodeContext)

	got := lt.buildPrompt(flag)
	if got != want {
		t.Fatalf("buildPrompt output changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Determinism: the same input must always produce the same prompt.
	if again := lt.buildPrompt(flag); again != got {
		t.Fatalf("buildPrompt is not deterministic for identical input")
	}
}

// TestParseResponse covers the LLM response parser with well-formed,
// malformed, and empty content — parseResponse is expected to never panic
// and to fall back to a permissive default when it can't understand the
// model's output.
func TestParseResponse(t *testing.T) {
	lt := &LLMTriager{}

	tests := []struct {
		name     string
		response string
		want     TriageResult
	}{
		{
			name:     "well-formed JSON",
			response: `{"is_real": true, "confidence": 0.87, "explanation": "real vuln"}`,
			want:     TriageResult{IsReal: true, Confidence: 0.87, Explanation: "real vuln"},
		},
		{
			name:     "well-formed JSON surrounded by prose",
			response: "Sure, here you go:\n{\"is_real\": false, \"confidence\": 0.1, \"explanation\": \"false positive\"}\nHope that helps!",
			want:     TriageResult{IsReal: false, Confidence: 0.1, Explanation: "false positive"},
		},
		{
			name:     "no braces at all falls back to the permissive default",
			response: "This is definitely a real vulnerability, trust me.",
			want:     TriageResult{IsReal: true, Confidence: 0.5},
		},
		{
			name:     "empty response falls back to the permissive default",
			response: "",
			want:     TriageResult{IsReal: true, Confidence: 0.5},
		},
		{
			name:     "unterminated JSON (no closing brace) falls back to the default",
			response: `{"is_real": true, "confidence": 0.9`,
			want:     TriageResult{IsReal: true, Confidence: 0.5},
		},
		{
			name:     "braces present but not valid JSON falls back to the default",
			response: "{not valid json at all}",
			want:     TriageResult{IsReal: true, Confidence: 0.5},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lt.parseResponse(tt.response)
			if got != tt.want {
				t.Errorf("parseResponse(%q) = %+v, want %+v", tt.response, got, tt.want)
			}
		})
	}
}

// roundTripFunc lets a plain function satisfy http.RoundTripper, so each
// test case can script the fake Groq response without any real network call.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// groqResponse builds a minimal Groq/OpenAI-shaped chat-completion response
// body carrying the given assistant message content.
func groqResponse(content string) *http.Response {
	body := fmt.Sprintf(`{"choices":[{"message":{"content":%q}}]}`, content)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// TestTriageFlags_MockedLLM drives the full TriageFlags pipeline (prompt
// build -> HTTP call -> response parse -> confidence-threshold filter)
// against a mocked Groq transport, so no network access or real API key is
// needed to verify the end-to-end triage behavior.
func TestTriageFlags_MockedLLM(t *testing.T) {
	tests := []struct {
		name         string
		content      string // Groq response content field
		transportErr error  // simulate a network/HTTP failure instead
		wantKept     bool
		wantConf     float64
	}{
		{
			name:     "high-confidence well-formed response is kept",
			content:  `{"is_real": true, "confidence": 0.9, "explanation": "real"}`,
			wantKept: true,
			wantConf: 0.9,
		},
		{
			name:     "low-confidence well-formed response is filtered out",
			content:  `{"is_real": false, "confidence": 0.2, "explanation": "false positive"}`,
			wantKept: false,
			wantConf: 0.2,
		},
		{
			name:    "malformed response falls back to 0.5 confidence and is filtered out",
			content: "the model rambled instead of returning JSON",
			// parseResponse's default (0.5) is below the 0.6 keep threshold,
			// so a malformed LLM response silently drops the finding rather
			// than escalating it for human review.
			wantKept: false,
			wantConf: 0.5,
		},
		{
			name:         "transport error degrades confidence by 20% instead of failing the run",
			transportErr: fmt.Errorf("connection refused"),
			wantKept:     true, // starting confidence 0.9 * 0.8 = 0.72, still above threshold
			wantConf:     0.72,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := &LLMTriager{
				apiKey: "test-key",
				client: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if tt.transportErr != nil {
							return nil, tt.transportErr
						}
						return groqResponse(tt.content), nil
					}),
				},
			}

			input := []flagging.Flag{{VulnID: "v1", CWE: "CWE-89", Confidence: 0.9}}
			got, err := lt.TriageFlags(input)
			if err != nil {
				t.Fatalf("TriageFlags() error = %v", err)
			}

			kept := len(got) == 1
			if kept != tt.wantKept {
				t.Fatalf("kept = %v, want %v (result: %+v)", kept, tt.wantKept, got)
			}
			if kept {
				if diff := got[0].Confidence - tt.wantConf; diff > 1e-9 || diff < -1e-9 {
					t.Errorf("Confidence = %v, want %v", got[0].Confidence, tt.wantConf)
				}
			}
		})
	}
}
