package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	backendBaseURL = "https://api.us36.app.wiz.io/graphql"
	ipRateLimits   = make(map[string]*ipRateLimit)
	rateLimit      = 5             // Limit to 5 requests per client IP per hour
	resetDuration  = 1 * time.Hour // Reset rate limit every 1 hour per IP address
	mu             sync.Mutex
)

type ipRateLimit struct {
	count     int       // Number of requests made by the IP
	lastReset time.Time // Time when the count was last reset
}

func main() {
	http.HandleFunc("/oauth/token", handleOAuthTokenRequest)
	http.HandleFunc("/graphql", handleGraphQLRequest)
	log.Println("Starting Wiz API Accountant on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func handleOAuthTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract client_id, client_secret, and audience
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	audience := r.FormValue("audience")

	if clientID == "" || clientSecret == "" || audience == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Get the token
	response, err := getClientCredentialsToken(clientID, clientSecret, audience)
	if err != nil {
		http.Error(w, "Failed to get token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond with the full JSON response from getToken function
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func handleGraphQLRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	mu.Lock()
	// Ensure there's an entry for the clientIP
	info, exists := ipRateLimits[clientIP]
	if !exists {
		info = &ipRateLimit{}
		ipRateLimits[clientIP] = info
	}
	mu.Unlock()

	// Check and update rate limit for this IP
	if !canMakeRequest(clientIP) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Log the incoming request
	log.Printf("Received request from %s: %s %s", clientIP, r.Method, r.URL.String())
	log.Printf("Rate limit info for %s: count=%d, lastReset=%s", clientIP, info.count, info.lastReset)

	// Get the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
		return
	}
	splitToken := strings.Split(authHeader, "Bearer ")
	if len(splitToken) != 2 {
		http.Error(w, "Invalid Authorization header format", http.StatusBadRequest)
		return
	}
	token := splitToken[1]

	// Forward the request to the backend SaaS platform
	forwardRequest(w, r, token)
}

func getClientCredentialsToken(clientID, clientSecret, audience string) ([]byte, error) {
	client := &http.Client{}
	reqBody := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&audience=%s",
		clientID, clientSecret, audience)
	req, err := http.NewRequest("POST", "https://auth.app.wiz.io/oauth/token", strings.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body into a buffer
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Print the response body (for debugging purposes)
	fmt.Println("Response body:", string(bodyBytes))

	// Return the response body as-is
	return bodyBytes, nil
}

func forwardRequest(w http.ResponseWriter, r *http.Request, token string) {
	client := &http.Client{}

	// Prepare the request to backendBaseURL
	reqURL := backendBaseURL + r.RequestURI
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequest(r.Method, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set headers from original request
	req.Header = r.Header
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to send request to backend: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy headers and status code to the response writer
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("Error copying response body:", err)
	}
}

func canMakeRequest(clientIP string) bool {
	mu.Lock()
	defer mu.Unlock()

	info := ipRateLimits[clientIP]
	if info == nil {
		// If no info exists, create a new entry
		ipRateLimits[clientIP] = &ipRateLimit{count: 1, lastReset: time.Now()}
		return true
	}

	// Check if enough time has passed since last reset
	if time.Since(info.lastReset) >= resetDuration {
		// Reset the count and update last reset time
		info.count = 1
		info.lastReset = time.Now()
		return true
	}

	// Check if count is within limit
	if info.count < rateLimit {
		info.count++
		return true
	}

	return false
}

func init() {
	go resetCounts()
}

func resetCounts() {
	for {
		time.Sleep(resetDuration)
		mu.Lock()
		// Reset counts for each IP
		for ip := range ipRateLimits {
			ipRateLimits[ip] = &ipRateLimit{}
		}
		mu.Unlock()
	}
}
