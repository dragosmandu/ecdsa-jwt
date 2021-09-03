/*
   random_test.go

   Created by Dragos-Costin Mandu on 03/09/2021.
*/

package random_test

import (
	"testing"

	"github.com/dragosmandu/ecdsa-jwt/random"
)

var length = 20

func TestRandomBytes(t *testing.T) {
	b, err := random.Bytes(length)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != length {
		t.Fatalf("invalid bytes length: %d", len(b))
	}
}

func TestRandomString(t *testing.T) {
	str, err := random.String(length)
	if err != nil {
		t.Fatal(err)
	}

	if len(str) != length {
		t.Fatalf("invalid string %s length: %d", str, len(str))
	}

	t.Log(str)
}
