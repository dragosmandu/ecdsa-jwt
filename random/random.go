/*
   random.go

   Created by Dragos-Costin Mandu on 03/09/2021.
*/

package random

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Generates a random byte slice with given length.
func Bytes(length int) ([]byte, error) {
	b := make([]byte, length)
	n, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %v", err)
	}

	if n != length {
		return nil, fmt.Errorf("unmatching no read bytes with given length")
	}

	return b, nil
}

// Generates a random string with given length.
func String(length int) (string, error) {
	b, err := Bytes(length)
	if err != nil {
		return "", err
	}

	encStr := base64.RawURLEncoding.EncodeToString(b)[0:length]

	return encStr, nil
}
