package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/console"
	"github.com/ethereum/go-ethereum/crypto"
)

func decrypt(ks []byte) (*keystore.Key, error) {
	var key *keystore.Key
	passphrase, err := console.Stdin.PromptPassword("Passphrase for Key Store: ")
	if err == nil {
		key, err = keystore.DecryptKey(ks, passphrase)
	}
	return key, err
}

func keyFor(file string) (*keystore.Key, error) {
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return decrypt(f)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Error: must specify keystore file")
		fmt.Println("---------------------------------")
		fmt.Println("\nWARNING: This command prints the decrypted key directly to stdout.")
		fmt.Println("It's recommended to pipe/forward to avoid console logging the key.")
		fmt.Println("\nExamples:\ngethpkey path/to/keystore.json | pbcopy")
		fmt.Println("gethpkey path/to/keystore.json | xclip -sel clip")
		fmt.Println("gethpkey path/to/keystore.json > pkey.txt")
		os.Exit(1)
	}

	key, err := keyFor(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	b := crypto.FromECDSA(key.PrivateKey)
	h := hex.EncodeToString(b)
	fmt.Println(string(h))
}
