/*
   ecdsaParser.go

   Created by Dragos-Costin Mandu on 03/09/2021.
*/

package ecdsaParser

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Returns an ecdsa private key from a given file path, or error.
func ParsePrivateKeyFromFile(filePath string) (*ecdsa.PrivateKey, error) {
	block, err := getPemBlockFromFile(filePath)
	if err != nil {
		return nil, err
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// Returns an ecdsa public key from a given file path, or error.
func ParsePublicKeyFromFile(filePath string) (*ecdsa.PublicKey, error) {
	block, err := getPemBlockFromFile(filePath)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	switch pubKey := pubKey.(type) {
	case *ecdsa.PublicKey:
		return pubKey, nil

	default:
		return nil, fmt.Errorf("invalid public key type")
	}
}

func getPemBlockFromFile(filePath string) (*pem.Block, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", filePath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode block")
	}

	return block, nil
}
