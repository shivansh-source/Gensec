package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/flagging"
)

type LLMTriager struct {
	client *http.Client
	apiKey string
}

func NewLLMTriager() *LLMTriager {
	return &LLMTriager{
		client: &http.Client{},
		apiKey: config.GroqAPIKey(),
	}
}

func (lt *LLMTriager) TriageFlags(flags []flagging.Flag) ([]flagging.Flag, error) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🤖 PHASE 3: LLM TRIAGE & CONFIDENCE SCORING")
	fmt.Println(strings.Repeat("=", 60))

	triaged := []flagging.Flag{}

	for idx, flag := range flags {
		fmt.Printf("\n  [%d/%d] Triaging: %s (%s)\n", idx+1, len(flags), flag.VulnID, flag.CWE)

		prompt := lt.buildPrompt(flag)

		response, err := lt.callGroq(prompt)
		if err != nil {
			fmt.Printf("    ⚠️  LLM error: %v\n", err)
			flag.Confidence *= 0.8
			triaged = append(triaged, flag)
			continue
		}

		result := lt.parseResponse(response)

		flag.Confidence = result.Confidence
		if result.Explanation != "" {
			flag.Explanation = result.Explanation
		}

		fmt.Printf("    ✅ Confidence: %.2f%%\n", flag.Confidence*100)

		if flag.Confidence >= 0.6 {
			triaged = append(triaged, flag)
		} else {
			fmt.Printf("    ⏭️  FILTERED (low confidence)\n")
		}
	}

	fmt.Printf("\n✅ Triaged flags: %d/%d kept\n", len(triaged), len(flags))

	return triaged, nil
}

func (lt *LLMTriager) buildPrompt(flag flagging.Flag) string {
	return fmt.Sprintf(`You are a Go security expert analyzing a potential vulnerability.

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
}

func (lt *LLMTriager) callGroq(prompt string) (string, error) {
	url := "https://api.groq.com/openai/v1/chat/completions"

	requestBody, err := json.Marshal(map[string]interface{}{
		"model": config.GroqModel,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.0,
		"max_tokens":  300,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+lt.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := lt.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}

	return result.Choices[0].Message.Content, nil
}

func (lt *LLMTriager) parseResponse(response string) TriageResult {
	result := TriageResult{
		IsReal:     true,
		Confidence: 0.5,
	}

	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")

	if start != -1 && end != -1 && end > start {
		json.Unmarshal([]byte(response[start:end+1]), &result)
	}

	return result
}

func (lt *LLMTriager) CallGroqDirect(prompt string) (string, error) {
	url := "https://api.groq.com/openai/v1/chat/completions"

	requestBody, err := json.Marshal(map[string]interface{}{
		"model": config.GroqModel,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0.2,  // Slightly higher for creative fixes
		"max_tokens":  2000, // Larger for full code generation
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+lt.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := lt.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}

	return result.Choices[0].Message.Content, nil
}
