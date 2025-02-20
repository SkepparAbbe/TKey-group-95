package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

// funktionen tar in en url och tkey publik key, []uint8 = lista av 8 bitars unsigned integer
func sendPubkey(url string, pubkey []uint8) error {
	// förbered pubkey
	dataToSend := map[string]string{
		"public_key": hex.EncodeToString(pubkey),
	}

	//gör om data till json format kolla med andra gruppen vilket format de använder
	json_dataToSend, _ := json.Marshal(dataToSend)
	fmt.Print(json_dataToSend)

	//url där data ska skickas, det som skickas är json-data, newbuffer läser av från json på de som ska skickas
	send, err := http.Post(url, "application/json", bytes.NewBuffer(json_dataToSend))
	if err != nil {
		fmt.Println("pubkey kunde inte skickas", err)
	}
	defer send.Body.Close() // send = *http.Response , defer stänger anslutning när vi är klara
	return nil              //samma som void i java returnar inget
}
