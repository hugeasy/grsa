package main

import (
	"encoding/base64"
	"fmt"
	"github.com/hugeasy/grsa"
	"log"
)

func main() {
	// generate
	keyPair, err := grsa.Generate(1024, grsa.PKCS8)
	if err != nil {
		log.Fatal("generate RSA key pair error", err)
	}

	keyPair.ToHex()

	privateKey, publicKey, err := keyPair.ToPEM()
	if err != nil {
		log.Fatal("RSA key pair to PEM error", err)
	}

	fmt.Println(privateKey)
	fmt.Println(publicKey)

	// encrypt
	ciphertext, err := grsa.EncryptByPrivateKey(privateKey, []byte("hello world"))
	if err != nil {
		log.Fatal("RSA enctype error", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))
}
