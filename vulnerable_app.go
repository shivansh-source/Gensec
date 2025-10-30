package main

import (
	"crypto/md5" 
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec" 
	_ "github.com/go-sql-driver/mysql"
)

var adminPassword = "supersecretpassword123!"

func getSystemStatus(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// Vulnerable: attacker can inject commands like "127.0.0.1; rm -rf /"
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n", err)
		return
	}
	fmt.Fprintf(w, "Output: %s\n", out)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", "user:"+dbPassword+"@/dbname")
	defer db.Close()

	userID := r.URL.Query().Get("id")
	// Vulnerable: attacker can inject SQL like "' OR '1'='1"
	query := "SELECT name, email FROM users WHERE id = '" + userID + "'"
	rows, _ := db.Query(query)
	defer rows.Close()

	for rows.Next() {
		var name, email string
		rows.Scan(&name, &email)
		fmt.Fprintf(w, "Name: %s, Email: %s\n", name, email)
	}
}

func hashPassword(password string) string {
	// Vulnerable: MD5 is cryptographically broken
	hasher := md5.New()
	hasher.Write([]byte(password))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// BUG 5: Missing TLS - HTTP instead of HTTPS for sensitive data
func setupServer() {
	fmt.Println("Admin Password:", adminPassword)
	fmt.Println("Hashed 'test':", hashPassword("test"))

	http.HandleFunc("/status", getSystemStatus)
	http.HandleFunc("/user", getUser)
	
	certFile := "path_to_your_cert.pem"
	keyFile := "path_to_your_key.pem"
	log.Fatal(http.ListenAndServeTLS(":8080", certFile, keyFile, nil))
}

// BUG 6: Unsafe File Operations - No input validation, possible path traversal
func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Vulnerable: attacker can use "../../../etc/passwd" to access files outside intended directory
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n", err)
		return
	}
	w.Write(data)
}

// BUG 7: Improper Error Handling - Logging sensitive information
func loginUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	password := r.URL.Query().Get("pass")

	// Vulnerable: hardcoded credentials and logging sensitive data
	if username == "admin" && password == adminPassword {
		fmt.Println("User logged in:", username, "Password:", password) // Logs password!
		fmt.Fprintf(w, "Login successful\n")
	} else {
		fmt.Fprintf(w, "Login failed\n")
	}
}

// BUG 8: No Input Validation - Buffer overflow risk
func processUserData(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	// Vulnerable: no length check, potential buffer overflow in Go (though Go has better memory safety)
	var buffer [32]byte
	copy(buffer[:], data)
	fmt.Fprintf(w, "Data received: %s\n", string(buffer[:]))
}

// BUG 9: Race Condition - Shared state without synchronization
var userCount = 0

func incrementUserCount(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: concurrent access to userCount without mutex protection
	userCount++
	fmt.Fprintf(w, "User count: %d\n", userCount)
}

// BUG 10: Insecure Deserialization (using eval-like patterns)
func executeUserCode(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	// Vulnerable: executing arbitrary code from user input (simplified example)
	// In real Go, this would require reflection or script evaluation
	result := evaluateExpression(code)
	fmt.Fprintf(w, "Result: %s\n", result)
}

func evaluateExpression(expr string) string {
	// Simplified dangerous function that could execute arbitrary code
	return fmt.Sprintf("Expression: %s", expr)
}

// Additional endpoint with XSS vulnerability
func displayUserMessage(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("msg")
	// Vulnerable: XSS attack - message not sanitized before output
	fmt.Fprintf(w, "<html><body>Message: %s</body></html>", message)
}

// BONUS BUG: Using os/exec with user input via shell
func searchLogs(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("search")
	// Vulnerable: command injection through grep
	cmd := exec.Command("bash", "-c", "grep "+searchTerm+" /var/log/app.log")
	out, _ := cmd.Output()
	fmt.Fprintf(w, "Search results: %s\n", out)
}

// Insecure random number generation
func generateToken() string {
	// Just an example - using predictable token generation
	return fmt.Sprintf("%d", len(adminPassword))
}

// Weak password strength
func isPasswordStrong(password string) bool {
	// Vulnerable: weak password validation
	return len(password) > 3 // Too weak!
}

// Sensitive data in response headers
func setResponseHeaders(w http.ResponseWriter) {
	// Vulnerable: exposing sensitive server information
	w.Header().Set("X-Admin-Password", adminPassword)
	w.Header().Set("Server", "CustomServer/1.0 (Built-in Admin: admin123!@#)")
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, "{\"status\": \"healthy\", \"secret\": \"%s\"}", adminPassword)
}

func adminPanel(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: admin panel with no authentication check
	fmt.Fprintf(w, "Admin Panel - Password: %s\n", adminPassword)
}

func main() {
	fmt.Println("Starting vulnerable application...")
	fmt.Println("Admin credentials - User: admin, Pass:", adminPassword)
	fmt.Println("DB Password:", dbPassword)

	setupServer()
}
