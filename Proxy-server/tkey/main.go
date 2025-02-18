package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const signerPath = "/home/amanch/tkeycthKod/appar/app.bin" //app.bin filen för signer

func main() {

	fmt.Println("Starting Tillitis Key Client")

	tk := tkeyclient.New()     // gör tkey struct
	tk.Connect("/dev/ttyACM0") // porten för tkey anslutning
	defer tk.Close()

	password := []byte("hej123")
	// ger unika nycklar beroende på password
	tk.LoadAppFromFile(signerPath, password) // sätt till nil om inget uss ska användas

	// skapa signer objekt
	signer := tkeysign.New(tk)
	pubkey, _ := signer.GetPubkey() //extrahera pubkey

	fmt.Print("offentligNyckel: ")
	fmt.Print(hex.EncodeToString(pubkey))
	// skapa medelande som ska signeras
	medelande := []byte("hemligtt")
	signature, _ := signer.Sign(medelande)

	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println(" ")
	fmt.Println(" ")

	fmt.Println("hashad medelande: ")
	fmt.Println(hex.EncodeToString(signature))
	fmt.Println("offentligNyckel: ")
	fmt.Println(hex.EncodeToString(pubkey))

}
