package cidaasinterceptor

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Jwks struct containing a list of keys to verify a signature of token
type Jwks struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey struct containing data of a key to verify a signature of token
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type cidaasTokenClaims struct {
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

// getKey based on kid in token and check in jwks
func getKey(token *jwt.Token, jwks Jwks) (*rsa.PublicKey, error) {
	// loop over jwks array and find key for kid of the token header
	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			pub, err := extractPublicKeyFromJWK(jwks.Keys[k])
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
	}
	err := errors.New("unable to find appropriate key")
	return nil, err
}

// getKeys call the JWKS endpoint
func getKeys(uri string) (Jwks, error) {
	// call JWKS endpoint
	var jwks = Jwks{}
	resp, err := http.Get(uri)
	// check if any error when retrieving the JWKS
	if err != nil {
		return jwks, err
	}
	defer resp.Body.Close()
	// Decode JWKS to JWKS[] type
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return jwks, err
	}
	return jwks, nil
}

func extractPublicKeyFromJWK(jwk JSONWebKey) (publicKey *rsa.PublicKey, err error) {
	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("base64 decoding failed")
	}
	e := 0
	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Fatal("need to decode e:", jwk.E)
		return nil, errors.New("e is not the expected default")
	}
	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}
	return pk, nil
}
