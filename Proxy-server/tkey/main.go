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

	//signer := createSigner()
	http.HandleFunc("/registration", registrationHandler)
	//http.HandleFunc("/login", loginHandler)

	fmt.Println("Server running on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
	//pubkey, _ := signer.GetPubkey() // Extract public key

	//fmt.Print("offentligNyckel: ")
	//fmt.Print(hex.EncodeToString(pubkey))

	// Create mock challenge to sign
	//challenge := []byte("hemligtt")

	// Sign the challenge
	//signature, _ := signer.Sign(challenge)

	/*
		fmt.Println("hashad medelande: ")
		fmt.Println(hex.EncodeToString(signature))
		fmt.Println("offentligNyckel: ")
	*/
	//fmt.Println(hex.EncodeToString(pubkey))

}

func loginHandler() {

}

func registrationHandler(w http.ResponseWriter, r *http.Request) {

	signer := createSigner()
	defer signer.Close() //problem annars efter första förfrågan defer menas att det alltid körs i slutet av funktionen
	//läser in challengen
	challenge, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	signature, _ := signer.Sign(challenge)
	fmt.Println("signature")
	fmt.Print(signature)
	publicKey, _ := signer.GetPubkey()
	fmt.Println("publickey")
	fmt.Print(publicKey)
	//response := map[string]string{"publicKey": string(re), "signature": string(signature)}

	// Skapa JSON-respons
	/*
		response := map[string]string{
			"publicKey": hex.EncodeToString(re),
			"signature": hex.EncodeToString(signature),
		}
	*/
	response := map[string]string{
		"publicKey": base64.StdEncoding.EncodeToString(publicKey), // Omvandla publicKey (byte-array) till Base64-sträng
		"signature": base64.StdEncoding.EncodeToString(signature), // Omvandla signature (byte-array) till Base64-sträng
	}
	fmt.Print("response")
	fmt.Print(response)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

func portConfig() []byte {
	port, err := os.ReadFile("config.txt") // Configure your port in config.txt
	if err != nil {
		log.Fatal("Error reading config file:", err)
	}
	return port
}

func createSigner() tkeysign.Signer {
	fmt.Println("Starting Tillitis Key Client")

	port := portConfig()

	tk := tkeyclient.New()

	tk.Connect(string(port))
	//tk.Close()

	fmt.Println("Successfully connected to port:", string(port))
	// Load application from file
	tk.LoadAppFromFile(signerPath, nil)

	// Create and return signer object
	signer := tkeysign.New(tk)
	return signer
}

/*
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
*/

/*

main
	start tkey
	/login endpoint
	/register endpoint

*/
