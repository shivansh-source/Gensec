package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// THIS IS THE VULNERABLE LINE - Make sure it looks like this:
	userID := r.URL.Query().Get("id")
	query := "SELECT name, email FROM users WHERE id = '" + userID + "'" // <-- Check this line carefully

	// Run the query
	rows, err := db.Query(query)
	if err != nil {
		log.Print(err)
		return
	}
	defer rows.Close()

	// ... (code to process rows) ...
	fmt.Println("Query successful")
}

func main() {
	http.HandleFunc("/user", getUserHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
