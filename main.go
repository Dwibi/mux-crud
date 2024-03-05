package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var db *sql.DB

type Book struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

func main() {
	// Load environment variables
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable is not set")
	}

	// Get database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Check if the "books" table exists. If not, create it.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS books (
			id SERIAL PRIMARY KEY,
			title TEXT NOT NULL,
			author TEXT NOT NULL
		)
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Create router
	router := mux.NewRouter()

	// Define routes.
	router.HandleFunc("/books", getBooks).Methods("GET")
	router.HandleFunc("/books/{id}", getBook).Methods("GET")
	router.HandleFunc("/books", createBook).Methods("POST")
	router.HandleFunc("/books/{id}", updateBook).Methods("PUT")
	router.HandleFunc("/books/{id}", deleteBook).Methods("DELETE")

	// Start the server
	fmt.Println("Server listening on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func getBooks(w http.ResponseWriter, r *http.Request) {
	// Get books from database
	rows, err := db.Query("SELECT id, title, author FROM books")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Iterate ever the rows and build a slice
	books := []Book{}

	for rows.Next() {
		var book Book
		err := rows.Scan(&book.ID, &book.Title, &book.Author)
		if err != nil {
			log.Fatal(err)
		}
		books = append(books, book)
	}

	// Convert the slice of Book objects to JSON and write it to the response.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(books)
}

func getBook(w http.ResponseWriter, r *http.Request) {
	// Get ID from request
	vars := mux.Vars(r)
	id := vars["id"]

	// Query the database to get the book with the specified ID
	var book Book
	err := db.QueryRow("SELECT id, title, author FROM books WHERE id = $1", id).Scan(&book.ID, &book.Title, &book.Author)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		http.NotFound(w, r)
		return
	}

	// If the book is not found, return a 404 Not Found response
	if book.ID == 0 {
		http.NotFound(w, r)
		return
	}

	// Convert the slice of Book objects to JSON and write it to the response.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(book)
}

func createBook(w http.ResponseWriter, r *http.Request) {
	// Parse request body to get the book data
	var book Book
	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert new book to the database
	_, err = db.Exec("INSERT INTO books (title, author) VALUES ($1, $2)", book.Title, book.Author)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with success created message
	w.WriteHeader(http.StatusCreated)
}

func updateBook(w http.ResponseWriter, r *http.Request) {
	// Get ID from request
	vars := mux.Vars(r)
	id := vars["id"]

	// Parse request body to get the book data
	var book Book
	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the book with the specified ID exists
	// var existingID int
	// err = db.QueryRow("SELECT id FROM books WHERE id = $1", id).Scan(&existingID)
	// if err != nil {
	// 	if err == sql.ErrNoRows {
	// 		// If the book with the specified ID doesn't exist, return a 404 Not Found response
	// 		http.NotFound(w, r)
	// 		return
	// 	}
	// 	// If an error occurs during the query, return an appropriate HTTP error response
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// update book to the database
	result, err := db.Exec("UPDATE books SET title = $1, author = $2 WHERE id = $3;", book.Title, book.Author, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the update affected any rows
	numRowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if numRowsAffected == 0 {
		// If no rows were affected, it means the book with the specified ID doesn't exist
		http.NotFound(w, r)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusOK)
}

func deleteBook(w http.ResponseWriter, r *http.Request) {
	// Get ID from request
	vars := mux.Vars(r)
	id := vars["id"]

	// Check if the book with the specified ID exists
	// var existingID int
	// err = db.QueryRow("SELECT id FROM books WHERE id = $1", id).Scan(&existingID)
	// if err != nil {
	// 	if err == sql.ErrNoRows {
	// 		// If the book with the specified ID doesn't exist, return a 404 Not Found response
	// 		http.NotFound(w, r)
	// 		return
	// 	}
	// 	// If an error occurs during the query, return an appropriate HTTP error response
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	// delete book to the database
	result, err := db.Exec("DELETE FROM books WHERE id = $1", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the update affected any rows
	numRowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if numRowsAffected == 0 {
		// If no rows were affected, it means the book with the specified ID doesn't exist
		http.NotFound(w, r)
		return
	}

	// Respond with success message
	w.WriteHeader(http.StatusOK)
}
