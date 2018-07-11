package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"

	"github.com/ethereumproject/go-ethereum/common"
	"github.com/ethereumproject/go-ethereum/crypto"
)

var ErrDecrypt = errors.New("could not decrypt key with given passphrase")

type key struct {
	UUID string
	// to simplify lookups we also store the address
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey *ecdsa.PrivateKey
}

type web3v3 struct {
	ID      string     `json:"id"`
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Version int        `json:"version"`
}

// web3v3 is a version 1 encrypted key store record.
type web3v1 struct {
	ID      string     `json:"id"`
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Version string     `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

// decryptKey decrypts a key from a JSON blob, returning the private key itself.
func decryptKey(web3JSON []byte, secret string) (*key, error) {
	// Parse the JSON into a simple map to fetch the key version
	m := make(map[string]interface{})
	if err := json.Unmarshal(web3JSON, &m); err != nil {
		return nil, err
	}

	// Depending on the version try to parse one way or another
	var (
		keyBytes []byte
		keyUUID  string
	)
	if version, ok := m["version"].(string); ok && version == "1" {
		w := new(web3v1)
		if err := json.Unmarshal(web3JSON, w); err != nil {
			return nil, err
		}

		keyUUID = w.ID

		var err error
		keyBytes, err = decryptKeyV1(w, secret)
		if err != nil {
			return nil, err
		}
	} else {
		w := new(web3v3)
		if err := json.Unmarshal(web3JSON, w); err != nil {
			return nil, err
		}
		if w.Version != 3 {
			return nil, fmt.Errorf("unsupported Web3 version: %v", version)
		}

		keyUUID = w.ID

		var err error
		keyBytes, err = decryptKeyV3(w, secret)
		if err != nil {
			return nil, err
		}
	}

	k := crypto.ToECDSA(keyBytes)
	return &key{
		UUID:       keyUUID,
		Address:    crypto.PubkeyToAddress(k.PublicKey),
		PrivateKey: k,
	}, nil
}

func decryptKeyV1(keyProtected *web3v1, secret string) (keyBytes []byte, err error) {
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, secret)
	if err != nil {
		return nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}

	plainText, err := aesCBCDecrypt(crypto.Keccak256(derivedKey[:16])[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return plainText, err
}

func decryptKeyV3(keyProtected *web3v3, secret string) (keyBytes []byte, err error) {
	if keyProtected.Crypto.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, secret)
	if err != nil {
		return nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return plainText, err
}

func getKDFKey(cryptoJSON cryptoJSON, secret string) ([]byte, error) {
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == "scrypt" {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key([]byte(secret), salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", prf)
		}
		key := pbkdf2.Key([]byte(secret), salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}

func aesCBCDecrypt(key, cipherText, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(aesBlock, iv)
	paddedPlaintext := make([]byte, len(cipherText))
	decrypter.CryptBlocks(paddedPlaintext, cipherText)
	plaintext := pkcs7Unpad(paddedPlaintext)
	if plaintext == nil {
		return nil, ErrDecrypt
	}
	return plaintext, err
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

// From https://leanpub.com/gocrypto/read#leanpub-auto-block-cipher-modes
func pkcs7Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

// TODO: can we do without this when unmarshalling dynamic JSON?
// why do integers in KDF params end up as float64 and not int after
// unmarshal?
func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func keyFileFor(key string, keyPath string) (string, error) {
	if strings.HasPrefix(key, "0x") {
		// Strip "0x" prefix
		key = key[2:]
	}
	file := path.Join(keyPath, "*--"+key)
	matches, err := filepath.Glob(file)
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("No keyfile found for key: %s", key)
	}
	return matches[0], err
}

func main() {
	keyArg := flag.String("key", "", "The key file to retrive the private key for (required)")
	pathArg := flag.String("path", "./blockchain/keystore", "Path of the Geth keystore")
	passwordArg := flag.String("password", "password", "The password for the key")

	flag.Parse()

	if *keyArg == "" {
		fmt.Println("Missing required `key` param\n")
		flag.Usage()
		os.Exit(1)
	}

	file, err := keyFileFor(*keyArg, *pathArg)
	if err != nil {
		log.Fatalln(err)
	}

	keyjson, err := ioutil.ReadFile(file)
	key, err := decryptKey(keyjson, *passwordArg)
	if err != nil {
		log.Fatalln(err)
	}

	//fmt.Printf("%x\n", key.PrivateKey.D.Bytes())
	fmt.Printf("%x\n", crypto.FromECDSA(key.PrivateKey))
}
