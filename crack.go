package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
)

type DataObject struct {
	Encrypted string `json:"e"`
	Salt      string `json:"s"`
	IV        string `json:"i"`
	// Version   string `json:"v"`
}

func main() {
	// Parse URL
	// NOTE: Test password is "test" and destination is https://jstrieb.github.io/link-lock/create/
	url, err := url.Parse("https://jstrieb.github.io/link-lock/#eyJ2IjoiMC4wLjEiLCJlIjoiWEk0ZS9GQkcxcko5Y1JCRVovUzk4Sk5IeGJwN0ljRk5MZUhTcVNrTUlpbW1mOFp4WlJIclEyK0lmY1liY3hOKy84WmlhMHdQYWFxcFhOcz0iLCJzIjoiMlFDNkIrcHcxckw4S0RiV1MvdWZqZz09IiwiaSI6IndCYkZZdHI4UFlNUittYnQifQ==")
	if err != nil {
		log.Fatal("Unable to parse URL.")
	}

	// Base64 decode URL fragment
	decoded, err := base64.URLEncoding.DecodeString(url.EscapedFragment())
	if err != nil {
		log.Fatal("Failed to base64-decode URL fragment.")
	}

	// Parse JSON object
	data := &DataObject{}
	if json.Unmarshal(decoded, data) != nil {
		log.Fatal("Failed to unmarshal JSON.")
	}

	fmt.Printf("%+v\n", data)
}
