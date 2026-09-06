package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/shivansh-source/gensec/internal/config"
	"github.com/shivansh-source/gensec/internal/flagging"
	"github.com/shivansh-source/gensec/internal/llm"
	"github.com/shivansh-source/gensec/internal/scanner"
)

//go:embed static/index.html
var webFS embed.FS

// scanResponse is what GET /api/scan returns to the dashboard.
type scanResponse struct {
	Path          string          `json:"path"`
	TotalFindings int             `json:"totalFindings"`
	TotalFlagged  int             `json:"totalFlagged"`
	Triaged       bool            `json:"triaged"`
	Findings      []flagging.Flag `json:"findings"`
	Warning       string          `json:"warning,omitempty"`
}

// cmdWeb starts a minimal read-only dashboard: point it at a path, it runs
// the same scan -> flag -> (optional) triage pipeline as `gensec scan` and
// renders the results in a browser. It never fixes anything or touches
// GitHub - view only, on purpose (see README).
//
// Not hardened for exposure beyond localhost/a trusted network: there's no
// auth, and the scanned path comes straight from client input.
func cmdWeb() {
	port := "8080"
	if len(os.Args) >= 3 && os.Args[2] != "" {
		port = os.Args[2]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/scan", handleScanAPI)

	addr := ":" + port
	fmt.Printf("\n🌐 GenSec web dashboard: http://localhost:%s\n", port)
	fmt.Println("   (read-only: scans and shows findings, never fixes or opens a PR)")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("web server error: %v", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleScanAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	scanRoot := req.Path
	if scanRoot == "" {
		scanRoot = "."
	}

	fileContent := loadFileContent(scanRoot)
	resp := scanResponse{Path: scanRoot}
	if len(fileContent) == 0 {
		resp.Warning = "no .go files found under this path"
		writeJSON(w, resp)
		return
	}

	multiScanner := scanner.NewMultiScanner(config.UserPlan(), scanRoot)
	findings, err := multiScanner.ScanAll()
	if err != nil {
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}
	resp.TotalFindings = len(findings)

	if len(findings) == 0 {
		writeJSON(w, resp)
		return
	}

	flagEngine := flagging.NewFlagEngine()
	flags, err := flagEngine.ProcessFindings(findings, fileContent)
	if err != nil {
		http.Error(w, fmt.Sprintf("flagging failed: %v", err), http.StatusInternalServerError)
		return
	}
	resp.TotalFlagged = len(flags)
	resp.Findings = flags

	if config.GroqAPIKey() != "" {
		triager := llm.NewLLMTriager()
		if triaged, err := triager.TriageFlags(flags); err == nil {
			resp.Findings = triaged
			resp.Triaged = true
		} else {
			resp.Warning = fmt.Sprintf("LLM triage failed, showing untriaged flags: %v", err)
		}
	} else {
		resp.Warning = "GROQ_API_KEY not set - showing untriaged flags (no confidence scoring)"
	}

	writeJSON(w, resp)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
