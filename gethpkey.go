package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

func decrypt(ks []byte) (*keystore.Key, error) {
	var key *keystore.Key
	fmt.Printf("Passphrase for keystore: ")
	p, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		key, err = keystore.DecryptKey(ks, string(p))
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
		fmt.Println("Writes the decrypted key to a file of the same name, with the extension '.pkey'")
		fmt.Println("Usage:")
		fmt.Println("\tgethpkey <keystore>")
		fmt.Println("\nExample:")
		fmt.Println("\tgethpkey path/to/keystore.json")
		os.Exit(1)
	}

	f := os.Args[1]
	key, err := keyFor(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	b := crypto.FromECDSA(key.PrivateKey)
	h := hex.EncodeToString(b)
	f = strings.TrimSuffix(f, filepath.Ext(f))

	err = ioutil.WriteFile(f+".pkey", []byte(h), 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
