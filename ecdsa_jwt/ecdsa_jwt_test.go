/*
   ecdsa_jwt_test.go

   Created by Dragos-Costin Mandu on 03/09/2021.
*/

package ecdsa_jwt_test

import (
	"testing"

	"github.com/dragosmandu/ecdsa-jwt/ecdsaParser"
	"github.com/dragosmandu/ecdsa-jwt/ecdsa_jwt"
)

var (
	token   string
	sigOpts = ecdsa_jwt.NewSigningOptions(5, 3600, ecdsa_jwt.ES256)
)

func TestNewJwt(t *testing.T) {
	claims := map[string]interface{}{
		"aud":  "audience",
		"sub":  "subject",
		"name": "john",
	}

	privKey, err := ecdsaParser.ParsePrivateKeyFromFile("testKeys/privateKey256.pem")
	if err != nil {
		t.Fatal(err)
	}

	token, err = sigOpts.NewToken(claims, privKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("token: %s", token)
}

func TestVerifyJwt(t *testing.T) {
	privKey, err := ecdsaParser.ParsePrivateKeyFromFile("testKeys/privateKey256.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = sigOpts.Verify(token, &privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("valid token")
}
