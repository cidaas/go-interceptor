package cidaasinterceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestSuccess_getKey tests that a key from a jwks can be selected successfully based on kid
func TestSuccess_getKey(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "kidtest"
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key1 := JSONWebKey{N: base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes()), E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}
	cert, err := getKey(token, jwks)
	assert.Nil(t, err)
	assert.Equal(t, rsakey.PublicKey.E, cert.E, "E should match")
	assert.Equal(t, rsakey.PublicKey.N, cert.N, "N should match")
}

// TestFailure_getKey tests that a proper error is returned when no kid is in the jwks
func TestFailure_getKey(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "kidtest"
	key1 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest1", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}
	cert, err := getKey(token, jwks)
	assert.NotNil(t, err)
	assert.Nil(t, cert, "Cert/Key should be a empty string")
	assert.Equal(t, "unable to find appropriate key", err.Error(), "error should be - Unable to find appropriate key")
}

func TestFailure_getKeys(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	_, _, close := createWellKnownMockServer(jwks)
	defer close()
	keys, err := getKeys("https://localhost:3000/test")
	assert.Error(t, err)
	assert.Len(t, keys.Keys, 0)
}

func TestSuccess_getKeys(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	_, jwksURI, close := createWellKnownMockServer(jwks)
	defer close()
	keys, err := getKeys(jwksURI)
	assert.NoError(t, err)
	assert.Len(t, keys.Keys, 2)
}
