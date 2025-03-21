package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const signerPath = "./app.bin" // Configure path for signer

func main() {
	tkeyclient.SilenceLogging() // Removes unnecessary prints in terminal

	http.HandleFunc("/registration", registrationHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server running on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func portConfig() (string, error) {
	port, err := tkeyclient.DetectSerialPort(false)

	if err != nil {
		return "", fmt.Errorf("tkey device is not connected: %v", err)
	}
	return port, nil
}

func enableCORS(w http.ResponseWriter, r *http.Request) {

	origin := r.Header.Get("Origin")

	allowedOrigins := []string{
		"http://localhost:8000",
		"https://t95.chalmers.it",
	}

	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
}

func createSignature(signer tkeysign.Signer, r *http.Request) ([]byte, error) {

	// Read the challenge from the request body
	challenge, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
	}
	defer r.Body.Close()

	signature, _ := signer.Sign(challenge)

	return signature, nil
}

func createSigner() (tkeysign.Signer, error) {
	port, err := portConfig()
	tk := tkeyclient.New()
	if err != nil {
		return tkeysign.Signer{}, err
	}
	tk.Connect(string(port))
	fmt.Println("Successfully connected to port:", string(port))

	// Load application from file
	tk.LoadAppFromFile(signerPath, nil)

	// Create and return signer object
	signer := tkeysign.New(tk)

	return signer, nil
}

// CreateResponse generates a response map with optional publicKey.
func CreateResponse(signature []byte, publicKey []byte, includePublicKey bool) map[string]string {
	response := map[string]string{
		"signature": base64.StdEncoding.EncodeToString(signature),
	}

	if includePublicKey {
		response["publicKey"] = base64.StdEncoding.EncodeToString(publicKey)
	}

	return response
}

// Sets the response map to the endpoint
func setResponse(w http.ResponseWriter, response map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Could't send response: %v", err)
	}
}

// Function to handle /login endpoint
func loginHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	signer, err := createSigner()
	if err != nil {
		http.Error(w, "No TKey device found", http.StatusBadRequest)
		log.Printf("Error creating signer: %v", err)
		return
	}
	// Ensure the signer is always closed after being used
	defer signer.Close()

	signature, err := createSignature(signer, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	response := CreateResponse(signature, nil, false)
	setResponse(w, response)
	log.Println("Signed challenge sent successfully")

}

// Function to handle /registration endpoint
func registrationHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	signer, err := createSigner()
	if err != nil {
		http.Error(w, "No TKey device found", http.StatusBadRequest)
		log.Printf("Error creating signer: %v", err)
		return
	}
	// Ensure the signer is always closed after being used
	defer signer.Close()
	signature, err := createSignature(signer, r)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	publicKey, _ := signer.GetPubkey()

	response := CreateResponse(signature, publicKey, true)

	setResponse(w, response)
	log.Println("Public key sent successfully")
}
