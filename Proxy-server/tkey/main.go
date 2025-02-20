package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const signerPath = "./app.bin" // Configure path for signer

func main() {

	fmt.Println("Starting Tillitis Key Client")

	port := portConfig()

	tk := tkeyclient.New()
	tk.Connect(string(port)) // Convert byte slice to string and connect to port
	defer tk.Close()

	fmt.Println("Successfully connected to port:", string(port))

	// Generates unique keys based on USS, nil = no USS
	tk.LoadAppFromFile(signerPath, nil)

	// Create signer object
	signer := tkeysign.New(tk)
	pubkey, _ := signer.GetPubkey() // Extract public key

	fmt.Print("offentligNyckel: ")
	fmt.Print(hex.EncodeToString(pubkey))

	// Create mock challenge to sign
	challenge := []byte("hemligtt")

	// Sign the challenge
	signature, _ := signer.Sign(challenge)

	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("hashad medelande: ")
	fmt.Println(hex.EncodeToString(signature))
	fmt.Println("offentligNyckel: ")
	fmt.Println(hex.EncodeToString(pubkey))

}

func portConfig() []byte {
	port, err := os.ReadFile("config.txt") // Configure your port in config.txt
	if err != nil {
		log.Fatal("Error reading config file:", err)
	}
	return port
}
