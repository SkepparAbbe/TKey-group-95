package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const signerPath = "./app.bin" // Configure path for signer

func main() {

	http.HandleFunc("/registration", registrationHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server running on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))

}

// Configure your port in config.txt
func portConfig() []byte {
	port, err := os.ReadFile("config.txt")
	if err != nil {
		log.Fatal("Error reading config file:", err)
	}
	return port
}

func createSignature(signer tkeysign.Signer, r *http.Request) []byte {

	// Read the challenge from the request body
	challenge, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	signature, _ := signer.Sign(challenge)

	fmt.Println("signature:", signature)

	return signature
}

func createSigner() tkeysign.Signer {

	fmt.Println("Starting Tillitis Key Client")

	port := portConfig()

	tk := tkeyclient.New()

	tk.Connect(string(port))
	fmt.Println("Successfully connected to port:", string(port))

	// Load application from file
	tk.LoadAppFromFile(signerPath, nil)

	// Create and return signer object
	signer := tkeysign.New(tk)

	// Ensure the signer is always closed when not returned
	//defer signer.Close()

	return signer
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
	json.NewEncoder(w).Encode(response)
}

// Function to handle /login endpoint
func loginHandler(w http.ResponseWriter, r *http.Request) {

	signer := createSigner()
	// Ensure the signer is always closed after being used
	defer signer.Close()
	signature := createSignature(signer, r)

	response := CreateResponse(signature, nil, false)
	fmt.Print("response")
	fmt.Print(response)

	setResponse(w, response)
}

// Function to handle /registration endpoint
func registrationHandler(w http.ResponseWriter, r *http.Request) {

	signer := createSigner()
	defer signer.Close()
	signature := createSignature(signer, r)

	publicKey, _ := signer.GetPubkey()
	fmt.Println("publickey")
	fmt.Print(publicKey)

	response := CreateResponse(signature, publicKey, true)
	fmt.Print("response")
	fmt.Print(response)

	setResponse(w, response)
}
