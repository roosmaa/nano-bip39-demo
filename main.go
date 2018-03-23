package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/roosmaa/nano-bip39-demo/internal/ed25519"
	"github.com/tyler-smith/go-bip39"
)

var bip32Path = Bip32Path{
	44 + 0x80000000,
	165 + 0x80000000,
	1 + 0x80000000,
}

func main() {
	mnemonic := flag.String("mnemonic", "", "BIP39 mnemonic (required)")
	password := flag.String("password", "", "BIP39 passphrase (optional)")
	flag.Parse()

	if *mnemonic == "" {
		panic("mnemonic argument missing")
	}

	seed, err := bip39.NewSeedWithErrorChecking(*mnemonic, *password)
	if err != nil {
		panic(err)
	}

	keyData, err := DerivePrivateKey(seed, bip32Path)
	if err != nil {
		panic(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(bytes.NewReader(keyData.Key))
	if err != nil {
		panic(err)
	}

	nanoAddress, err := EncodeAddress(publicKey)
	if err != nil {
		panic(err)
	}

	// Display mnemonic and keys
	fmt.Printf("Mnemonic: %#v\n", *mnemonic)
	fmt.Printf("Password: %#v\n", *password)
	fmt.Printf("Path: %s\n", bip32Path)
	fmt.Printf("Private key: %s\n", hex.EncodeToString(privateKey[:32]))
	fmt.Printf("Public key: %s\n", hex.EncodeToString(publicKey))
	fmt.Printf("Nano address: %s\n", nanoAddress)
}
