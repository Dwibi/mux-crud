package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type App struct {
	db          *sql.DB
	oauthConfig *oauth2.Config
}

type Book struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type User struct {
	Sub     string `json:"sub"` // User ID
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"` // URL of the user's profile picture
}

func main() {
	// Load environment variables
	godotenv.Load()
	app := App{}
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
	app.db = db
	app.oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8000/auth/google/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	// Create router
	router := mux.NewRouter()

	// Define routes.
	router.HandleFunc("/books", authMW(app.getBooks)).Methods("GET")
	router.HandleFunc("/books/{id}", authMW(app.getBook)).Methods("GET")
	router.HandleFunc("/books", authMW(app.createBook)).Methods("POST")
	router.HandleFunc("/books/{id}", authMW(app.updateBook)).Methods("PUT")
	router.HandleFunc("/books/{id}", authMW(app.deleteBook)).Methods("DELETE")

	// Handle Google OAuth login
	router.HandleFunc("/auth/google/login", app.handleGoogleLogin).Methods("GET")
	router.HandleFunc("/auth/google/logout", app.handleGoogleLogout).Methods("POST")
	router.HandleFunc("/auth/google/callback", app.handleGoogleCallback).Methods("GET")

	// Start the server
	fmt.Println("Server listening on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func (a *App) getBooks(w http.ResponseWriter, r *http.Request) {
	// Get books from database
	rows, err := a.db.Query("SELECT id, title, author FROM books")
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

func (a *App) getBook(w http.ResponseWriter, r *http.Request) {
	// Get ID from request
	vars := mux.Vars(r)
	id := vars["id"]

	// Query the database to get the book with the specified ID
	var book Book
	err := a.db.QueryRow("SELECT id, title, author FROM books WHERE id = $1", id).Scan(&book.ID, &book.Title, &book.Author)
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

func (a *App) createBook(w http.ResponseWriter, r *http.Request) {
	// Parse request body to get the book data
	var book Book
	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Insert new book to the database
	_, err = a.db.Exec("INSERT INTO books (title, author) VALUES ($1, $2)", book.Title, book.Author)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with success created message
	w.WriteHeader(http.StatusCreated)
}

func (a *App) updateBook(w http.ResponseWriter, r *http.Request) {
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
	result, err := a.db.Exec("UPDATE books SET title = $1, author = $2 WHERE id = $3;", book.Title, book.Author, id)
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

func (a *App) deleteBook(w http.ResponseWriter, r *http.Request) {
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
	result, err := a.db.Exec("DELETE FROM books WHERE id = $1", id)
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

func (a *App) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if the user already has the authToken cookie
	_, err := r.Cookie("authToken")
	if err == nil {
		// If authToken cookie exists, redirect the user to another page or display a message
		w.Write([]byte("You are already logged in"))
		return
	}

	// Redirect user to Google's consent screen
	url := a.oauthConfig.AuthCodeURL("state")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *App) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Retrieve authorization code from the query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for access token
	token, err := a.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Use token to access Google APIs or retrieve user information
	client := a.oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Decode User response body
	var userInfo User
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if user already exists in the database
	var count int
	err = a.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", userInfo.Email).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count == 0 {
		// User doesn't exist, create a new account
		_, err := a.db.Exec("INSERT INTO users (email, name, picture_url) VALUES ($1, $2, $3)", userInfo.Email, userInfo.Name, userInfo.Picture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Set user token cookie
	cookie := &http.Cookie{
		Name:    "authToken",
		Value:   token.AccessToken,
		Path:    "/",
		Expires: token.Expiry,
	}
	http.SetCookie(w, cookie)

	// Display success message
	w.Write([]byte("Authentication successful!"))
}

func authMW(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get cookie
		cookie, err := r.Cookie("authToken")

		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "Unauthorized!", http.StatusBadRequest)
			default:
				log.Println(err)
				http.Error(w, "server error", http.StatusInternalServerError)
			}
			return
		}

		// Create token source with the OAuth2 token
		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cookie.Value})

		// Create OAuth2 client with the token source
		oauthClient := oauth2.NewClient(context.Background(), tokenSource)

		// Send request to Google's tokeninfo endpoint to validate the token
		resp, err := oauthClient.Get("https://www.googleapis.com/oauth2/v3/tokeninfo")
		if err != nil {
			return
		}

		defer resp.Body.Close()

		// Check if response status code is OK
		if resp.StatusCode != http.StatusOK {
			return
		}

		next(w, r)
	}
}

func (a *App) handleGoogleLogout(w http.ResponseWriter, r *http.Request) {

	// Get token from user request cookie
	userToken, err := r.Cookie("authToken")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Revoke token process
	token := &oauth2.Token{AccessToken: userToken.Value}

	// Create an OAuth2 client with the token source
	oauthClient := a.oauthConfig.Client(context.Background(), token)

	// Send a POST request to revoke the token
	resp, err := oauthClient.PostForm("https://oauth2.googleapis.com/revoke", url.Values{
		"token": {token.AccessToken},
	})
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Bad request", http.StatusBadRequest)
		fmt.Printf("failed to revoke token: %s", resp.Status)
		return
	} else {
		fmt.Println("Token revoked")
	}

	// Clear the authToken cookie
	cookie := &http.Cookie{
		Name:    "authToken",
		Value:   "",
		Expires: time.Now().AddDate(0, 0, -1),
		Path:    "/", // Ensure the cookie is deleted across all paths
	}

	http.SetCookie(w, cookie)
	w.Write([]byte("Logout successful!"))
}
