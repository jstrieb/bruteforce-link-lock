package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"golang.org/x/crypto/pbkdf2"
)

type DataObject struct {
	Encrypted string `json:"e"`
	Salt      string `json:"s"`
	IV        string `json:"i"`
	// Version   string `json:"v"`
}

// ParseUrl extracts a base64 encoded JSON string from the fragment of a URL, if
// possible. Otherwise it raises fatal errors.
func ParseUrl(rawUrl string) *DataObject {
	// Parse URL
	// NOTE: Test password is "test" and destination is https://jstrieb.github.io/link-lock/create/
	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Fatal("Unable to parse the URL.")
	}

	// Base64 decode URL fragment
	decoded, err := base64.StdEncoding.DecodeString(url.EscapedFragment())
	if err != nil {
		log.Fatal("Failed to base64 decode the URL fragment.")
	}

	// Parse JSON object
	data := &DataObject{}
	if json.Unmarshal(decoded, data) != nil {
		log.Fatal("Failed to unmarshal JSON.")
	}

	return data
}

// Try to decrypt the encrypted data object with the password. Return the
// plaintext if decrypted, and a boolean status value. Fail catastrophically if
// any parsing step fails.
func TryDecrypt(password string, data *DataObject) (string, bool) {
	// Perform key derivation
	salt, err := base64.StdEncoding.DecodeString(data.Salt)
	if err != nil {
		log.Fatal("Failed to base64 decode the salt.")
	}
	k := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Generate an AES decoder for the given key
	block, err := aes.NewCipher(k)
	if err != nil {
		log.Fatal("Failed to create a new cipher from the key.")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("Failed to create a new GCM wrapping from the block cipher.")
	}

	// Base64 decode the IV and encrypted key material
	iv, err := base64.StdEncoding.DecodeString(data.IV)
	if err != nil {
		log.Fatal("Failed to base64 decode the IV.")
	}
	encrypted, err := base64.StdEncoding.DecodeString(data.Encrypted)
	if err != nil {
		log.Fatal("Failed to base64 decode the ciphertext.")
	}

	// Decrypt ciphertext
	plaintext, err := aesgcm.Open(nil, iv, encrypted, nil)
	if err != nil {
		return "", false
	}

	return string(plaintext), true
}

func main() {
	data := ParseUrl("https://jstrieb.github.io/link-lock/#eyJ2IjoiMC4wLjEiLCJlIjoiWEk0ZS9GQkcxcko5Y1JCRVovUzk4Sk5IeGJwN0ljRk5MZUhTcVNrTUlpbW1mOFp4WlJIclEyK0lmY1liY3hOKy84WmlhMHdQYWFxcFhOcz0iLCJzIjoiMlFDNkIrcHcxckw4S0RiV1MvdWZqZz09IiwiaSI6IndCYkZZdHI4UFlNUittYnQifQ==")

	plaintext, ok := TryDecrypt("test", data)
	if !ok {
		fmt.Println("Decryption failed!")
	}
	fmt.Println(string(plaintext))
}
