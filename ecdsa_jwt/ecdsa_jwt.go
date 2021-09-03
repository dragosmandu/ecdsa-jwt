/*
   ecdsa_jwt.go

   Created by Dragos-Costin Mandu on 03/09/2021.
*/

package ecdsa_jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"github.com/dragosmandu/ecdsa-jwt/random"
)

type Alg string

type SigningOptions struct {
	hash        crypto.Hash
	alg         Alg
	lifetimeSec int64
	nonceLen    int
	keySize     int
}

const (

	// Encrypts token with ecdsa with P-256 curve and SHA256 hash.
	ES256 Alg = "ES256"

	// Encrypts token with ecdsa with P-384 curve and SHA384 hash.
	ES384 Alg = "ES384"

	// Encrypts token with ecdsa with P-521 curve and SHA512 hash.
	ES512 Alg = "ES512"
)

// The nonce is a random string of nonceLen length. If nonceLen is 0, no nonce will be added.
// Lifetime is the time the token is valid from iat.
func NewSigningOptions(nonceLen int, lifetimeSec int64, alg Alg) *SigningOptions {
	var hash crypto.Hash
	var keySize int

	switch alg {
	case ES256:
		hash = crypto.SHA256
		keySize = 32

	case ES384:
		hash = crypto.SHA384
		keySize = 48

	case ES512:
		hash = crypto.SHA512
		keySize = 66
	}

	return &SigningOptions{
		hash:        hash,
		alg:         alg,
		lifetimeSec: lifetimeSec,
		nonceLen:    nonceLen,
		keySize:     keySize,
	}
}

// Creates a new jwt token, adding registered claims and encrypted with given private key.
// Issued at and expiration (iat + lifetime) will be added automatically.
func (sigOpts *SigningOptions) NewToken(regClaims map[string]interface{}, privKey *ecdsa.PrivateKey) (string, error) {
	header := sigOpts.createHeader()
	payload, err := sigOpts.createPayload(regClaims)
	if err != nil {
		return "", err
	}

	signingStr, err := createSigningStr(header, payload)
	if err != nil {
		return "", err
	}

	sig, err := sigOpts.sign(signingStr, privKey)
	if err != nil {
		return "", err
	}

	return signingStr + "." + sig, nil
}

// Verifies the token with given public key. If the verification fails, or the token signature
// is invalid will return an error. This method doesn't validate the token claims.
func (sigOpts *SigningOptions) Verify(token string, pubKey *ecdsa.PublicKey) error {
	signingStr, sigStr, err := split(token)
	if err != nil {
		return err
	}

	return sigOpts.verify(signingStr, sigStr, pubKey)
}

func (sigOpts *SigningOptions) createHeader() map[string]interface{} {
	return map[string]interface{}{
		"alg": sigOpts.alg,
		"typ": "JWT",
	}
}

func (sigOpts *SigningOptions) createPayload(regClaims map[string]interface{}) (map[string]interface{}, error) {
	payload := make(map[string]interface{})
	iat := time.Now().Unix()

	for k, v := range regClaims {
		payload[k] = v
	}

	payload["iat"] = iat
	payload["exp"] = iat + sigOpts.lifetimeSec

	if sigOpts.nonceLen > 0 {
		nonce, err := random.String(sigOpts.nonceLen)
		if err != nil {
			return nil, err
		}

		payload["nonce"] = nonce
	}

	return payload, nil
}

func createSigningStr(header, payload map[string]interface{}) (string, error) {
	headerb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %v", err)
	}

	payloadb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}

	encHeader := base64.RawURLEncoding.EncodeToString(headerb)
	encPayload := base64.RawURLEncoding.EncodeToString(payloadb)
	signingStr := encHeader + "." + encPayload

	return signingStr, nil
}

func (sigOpts *SigningOptions) sign(signingStr string, privKey *ecdsa.PrivateKey) (string, error) {
	hasher, err := sigOpts.hasher(signingStr)
	if err != nil {
		return "", err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, hasher.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %v", err)
	}

	sigb := make([]byte, sigOpts.keySize*2)

	r.FillBytes(sigb[0:sigOpts.keySize])
	s.FillBytes(sigb[sigOpts.keySize:])

	sigStr := base64.RawURLEncoding.EncodeToString(sigb)

	return sigStr, nil
}

func split(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid token")
	}

	signingStr := parts[0] + "." + parts[1]
	sigStr := parts[2]

	return signingStr, sigStr, nil
}

func (sigOpts *SigningOptions) verify(signingStr, sigStr string, pubKey *ecdsa.PublicKey) error {
	sigb, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	if len(sigb) != sigOpts.keySize*2 {
		return fmt.Errorf("invalid signature size")
	}

	hasher, err := sigOpts.hasher(signingStr)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(sigb[:sigOpts.keySize])
	s := big.NewInt(0).SetBytes(sigb[sigOpts.keySize:])

	if isValid := ecdsa.Verify(pubKey, hasher.Sum(nil), r, s); isValid {
		return nil
	}

	return fmt.Errorf("invalid signature")
}

func (sigOpts *SigningOptions) hasher(signingStr string) (hash.Hash, error) {
	if !sigOpts.hash.Available() {
		return nil, fmt.Errorf("unavailable hash")
	}

	hasher := sigOpts.hash.New()
	hasher.Write([]byte(signingStr))

	return hasher, nil
}
