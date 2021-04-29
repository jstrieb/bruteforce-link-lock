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
	"runtime"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type DataObjectTemplate struct {
	Encrypted string `json:"e"`
	Salt      string `json:"s"`
	IV        string `json:"i"`
	Version   string `json:"v"`
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
	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Println(err)
		log.Fatal("Unable to parse the URL.")
	}

	// Base64 decode URL fragment
	urlJson, err := base64.StdEncoding.DecodeString(url.EscapedFragment())
	if err != nil {
		log.Println(err)
		log.Fatal("Failed to base64 decode the URL fragment.")
	}

	// Parse JSON object. NOTE: fields are still individually base64 encoded
	encodedData := &DataObjectTemplate{}
	err = json.Unmarshal(urlJson, encodedData)
	if err != nil {
		log.Println(err)
		log.Fatal("Failed to unmarshal JSON.")
	}

	// Handle default cases for missing salt and/or IV
	if encodedData.Salt == "" {
		switch encodedData.Version {
		case "0.0.1":
			encodedData.Salt = "7Oen+c9fyeukYvYasK5I+Q=="
		}
	}
	if encodedData.IV == "" {
		switch encodedData.Version {
		case "0.0.1":
			encodedData.IV = "/+2UaQb/e8pzghB0"
		}
	}

	// Base64 decode byte fields from JSON object
	data := &DataObject{}
	salt, err := base64.StdEncoding.DecodeString(encodedData.Salt)
	if err != nil {
		log.Println(err)
		log.Fatal("Failed to base64 decode the salt.")
	}
	iv, err := base64.StdEncoding.DecodeString(encodedData.IV)
	if err != nil {
		log.Println(err)
		log.Fatal("Failed to base64 decode the IV.")
	}
	encrypted, err := base64.StdEncoding.DecodeString(encodedData.Encrypted)
	if err != nil {
		log.Println(err)
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
		log.Println(err)
		log.Fatal("Failed to create a new cipher from the key.")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
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

// TryCombos loops over combinations that come in over the channel and attempts
// to decrypt using the combination as a passphrase. Sends a message on the done
// channel when it has either exhausted the channel or found a solution.
func TryCombos(data *DataObject, comboChan chan string, done chan bool, countChan chan int) {
	for password := range comboChan {
		// Try a password
		plaintext, ok := TryDecrypt(password, data)
		if ok {
			log.Printf(`Decrypted link "%v"`, string(plaintext))
			log.Printf(`Password "%v"`, password)
			done <- true
			return
		}
		countChan <- 1
	}

	done <- false
}

// PrintProgress receives data about how many passwords have been attempted so
// far, and periodically prints out a status line
func PrintProgress(count chan int, frequency time.Duration) {
	start := time.Now()

	ticker := time.Tick(frequency * time.Second)
	total := 0.0 // Float for doing division later
	x := 0
	for {
		select {
		case x = <-count:
			total += float64(x)
		case <-ticker:
			rate := total / time.Since(start).Seconds()
			// Extra spaces at the end to handle carriage return weirdness and
			// slightly different string lengths
			fmt.Printf("Tried %v in %v at %d/s   \r", total, time.Since(start), int(rate))
		}
	}
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

	// Run a goroutine that sends progress updates
	countChan := make(chan int, 128)
	go PrintProgress(countChan, 1)
	defer fmt.Println("") // Let the last progress line remain

	length := 0
	for {
		keyspace := uint64(math.Pow(float64(len(*charset)), float64(length)))
		log.Printf("Trying %v passwords of length %v\n", keyspace, length)

		// Generate combinations to try
		comboChan := make(chan string, 128)
		go Combos(length, "", *charset, comboChan)

		// Try combinations in parallel and report when done.
		// NOTE: Can use all threads for decryption because computing
		// combinations is negligibly cheap in comparison (and thus doesn't need
		// its own thread)
		done := make(chan bool)
		numThreads := runtime.NumCPU()
		for i := 0; i < numThreads; i++ {
			go TryCombos(data, comboChan, done, countChan)
		}

		// Wait for a goroutine to find the answer, or for all to finish when
		// the combo channel closes
		for i := 0; i < numThreads; i++ {
			if <-done {
				return
			}
		}

		length++
	}
}
