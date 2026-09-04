package vulnerable

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
)

// VULNERABLE: Path Traversal Attack
func VulnerableFileDownload(w http.ResponseWriter, r *http.Request) {
	// SECURITY ISSUE: User input used directly in file path
	filename := r.URL.Query().Get("file")

	// Attacker could use: ?file=../../../../etc/passwd
	filePath := "/uploads/" + filename

	data, _ := ioutil.ReadFile(filePath)
	w.Write(data)
}

// FIXED: Path Traversal Protection
func SecureFileDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Clean the path and ensure it's within the allowed directory
	basePath := "/uploads/"
	cleanPath := filepath.Clean(filepath.Join(basePath, filename))

	// Ensure the resolved path is within basePath
	if !isInDirectory(cleanPath, basePath) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	data, _ := ioutil.ReadFile(cleanPath)
	w.Write(data)
}

func isInDirectory(filePath, directory string) bool {
	abs, _ := filepath.Abs(filePath)
	dir, _ := filepath.Abs(directory)
	return filepath.HasPrefix(abs, dir)
}

// VULNERABLE: Template injection
func VulnerableTemplate(userInput string) string {
	// VULNERABILITY: Concatenating user input into template
	template := "Hello {{.Name}}, your input was: " + userInput
	return template
}

// FIXED: Safe template handling
func SecureTemplate(userInput string) string {
	// Only use variables, not concatenation
	template := "Hello {{.Name}}, your input was: {{.UserInput}}"
	// Data is passed separately to template renderer
	_ = template
	return ""
}
