package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type DataObjectTemplate struct {
	Encrypted string `json:"e"`
	Salt      string `json:"s"`
	IV        string `json:"i"`
	// Version   string `json:"v"`
}

type DataObject struct {
	Encrypted []byte
	Salt      []byte
	IV        []byte
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
	encodedData := &DataObjectTemplate{}
	if json.Unmarshal(decoded, encodedData) != nil {
		log.Fatal("Failed to unmarshal JSON.")
	}

	// Base64 decode bytes
	// TODO: Handle default cases for missing salt and IV
	data := &DataObject{}
	salt, err := base64.StdEncoding.DecodeString(encodedData.Salt)
	if err != nil {
		log.Fatal("Failed to base64 decode the salt.")
	}
	iv, err := base64.StdEncoding.DecodeString(encodedData.IV)
	if err != nil {
		log.Fatal("Failed to base64 decode the IV.")
	}
	encrypted, err := base64.StdEncoding.DecodeString(encodedData.Encrypted)
	if err != nil {
		log.Fatal("Failed to base64 decode the ciphertext.")
	}

	data.Salt = salt
	data.IV = iv
	data.Encrypted = encrypted

	return data
}

// Try to decrypt the encrypted data object with the password. Return the
// plaintext if decrypted, and a boolean status value. Fail catastrophically if
// any parsing step fails.
func TryDecrypt(password string, data *DataObject) (string, bool) {
	// Perform key derivation
	k := pbkdf2.Key([]byte(password), data.Salt, 100000, 32, sha256.New)

	// Generate an AES decoder for the given key
	block, err := aes.NewCipher(k)
	if err != nil {
		log.Fatal("Failed to create a new cipher from the key.")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("Failed to create a new GCM wrapping from the block cipher.")
	}

	// Decrypt ciphertext
	plaintext, err := aesgcm.Open(nil, data.IV, data.Encrypted, nil)
	if err != nil {
		return "", false
	}

	return string(plaintext), true
}

// Combos sends all combinations of the charset of the given length through the
// channel.
func Combos(length int, prefix string, charset string, c chan string) {
	// If recursive depth is 0, close the channel when we finish
	if prefix == "" {
		defer close(c)
	}

	// Base case
	if length == 0 {
		c <- prefix
		return
	}

	// Inductive case
	for _, char := range charset {
		Combos(length-1, prefix+string(char), charset, c)
	}
}

func TryCombos(data *DataObject, comboChan chan string, done chan bool) {
	for password := range comboChan {
		// Try a password
		plaintext, ok := TryDecrypt(password, data)
		if ok {
			log.Println(string(plaintext))
			done <- true
			return
		}
	}

	done <- false
}

func main() {
	// Parse command line flags and arguments
	charset := flag.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Charset to use for cracking")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: crack [options] <Link Lock url>\nOptions:")
		flag.PrintDefaults()
		return
	}

	// Parse the URL
	url := flag.Arg(0)
	data := ParseUrl(url)

	length := 0
	done := make(chan bool)
	for {
		log.Printf("Trying %v passwords of length %v\n", math.Pow(float64(len(*charset)), float64(length)), length)

		// TODO: Adjust channel buffer size
		comboChan := make(chan string)
		go Combos(length, "", *charset, comboChan)

		go TryCombos(data, comboChan, done)
		if <-done {
			return
		}

		length++
	}
}
