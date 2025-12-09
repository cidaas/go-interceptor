package cidaasinterceptor

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func verifySignature(opts Options, endpoints cidaasEndpoints, jwks *Jwks, tokenString string, securityOpts SecurityOptions) *TokenData {
	// parse token
	token, err := jwt.ParseWithClaims(tokenString, &cidaasTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		pem, err := getKey(token, *jwks)
		if err != nil {
			log.Printf("Reloading keys for Kid : %v", token.Header["kid"])
			keys, err := getKeys(endpoints.JwksURI)
			if err != nil {
				return nil, err
			}
			*jwks = keys
			pem, err := getKey(token, *jwks)
			if err == nil {
				return pem, nil
			}
			return nil, fmt.Errorf("no key found for: %v", token.Header["kid"])
		}
		return pem, nil
	})
	// check if there was an error in parsing
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return nil
	}
	sub := ""
	aud := ""
	// check claims
	if claims, ok := token.Claims.(*cidaasTokenClaims); ok && token.Valid {
		if opts.Debug {
			log.Printf("Scopes: %v", claims.Scopes)
			log.Printf("Roles: %v", claims.Roles)
			log.Printf("Sub: %v", claims.Subject)
		}
		// check if sub is anonymous if not allowed
		isAnonymous := strings.EqualFold(claims.Subject, anonymousSub)
		if !securityOpts.AllowAnonymousSub && isAnonymous {
			return nil
		}
		// verify exp times in token data based on current timestamp
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			log.Printf("Token expired!, expiration: %v, now: %v", claims.ExpiresAt, time.Now())
			return nil
		}
		// verify issuer in token data based on baseURI given in options of interceptor
		if claims.Issuer != opts.BaseURI {
			log.Printf("Issuer mismatch, issuer: %v, base URI: %v", claims.Issuer, opts.BaseURI)
			return nil
		}

		// check for roles and scopes in token data
		if !checkScopesAndRoles(claims.Scopes, claims.Roles, securityOpts, isAnonymous) {
			return nil
		}
		sub = claims.Subject
		aud = claims.Audience[0]
	} else {
		log.Println("Issue with claims")
		return nil
	}
	return &TokenData{Sub: sub, Aud: aud}
}
