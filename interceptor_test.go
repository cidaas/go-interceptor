package cidaasinterceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewInterceptor_NoOptions(t *testing.T) {
	_, _, err := newInterceptor(Options{})
	assert.Error(t, err)
	assert.Equal(t, "no Base URI passed", err.Error())
}

func TestNewInterceptor_ErrorGettingWellKnown(t *testing.T) {
	_, _, err := newInterceptor(Options{BaseURI: "wrong"})
	assert.Error(t, err)
	fmt.Println(err)
	assert.Contains(t, err.Error(), "Get \"wrong/.well-known/openid-configuration\": unsupported protocol scheme")
}

func TestNewInterceptor_GetKeysError(t *testing.T) {
	uri, _, close := createWellKnownMockServer(Jwks{}, true)
	defer close()
	_, _, err := newInterceptor(Options{BaseURI: uri})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Get \"\": unsupported protocol scheme \"\"")
}

func TestNewInterceptor_Success(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	apis, resJwks, err := newInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.Equal(t, jwks, resJwks)
	assert.NotEmpty(t, apis.JwksURI)
}

func TestSuccess_CheckScopesAndRoles_ScopesAndRolesInToken(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	tokenRoles := []string{"USER", "DEVELOPER"}
	scopes := []string{"profile", "email"}
	roles := []string{"USER", "DEVELOPER"}
	opts := SecurityOptions{Scopes: scopes, Roles: roles}
	assert.True(t, checkScopesAndRoles(tokenScopes, tokenRoles, opts, false), "roles and scopes should match")
}

func TestSuccess_CheckScopesAndRoles_AdditionalScopesAndRoles(t *testing.T) {
	tokenScopes := []string{"profile", "email", "mobile"}
	tokenRoles := []string{"USER", "DEVELOPER", "MAINTAINER"}
	scopes := []string{"profile", "email"}
	roles := []string{"USER", "DEVELOPER"}
	opts := SecurityOptions{Scopes: scopes, Roles: roles}
	assert.True(t, checkScopesAndRoles(tokenScopes, tokenRoles, opts, false), "roles and scopes should match")
}

func TestSuccess_CheckScopes_ScopesInToken(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	scopes := []string{"profile", "email"}
	opts := SecurityOptions{Scopes: scopes}
	assert.True(t, checkScopesAndRoles(tokenScopes, nil, opts, false), "scopes should match")
}

func TestSuccess_CheckRoles_RolesInToken(t *testing.T) {
	tokenRoles := []string{"USER", "DEVELOPER"}
	roles := []string{"USER", "DEVELOPER"}
	opts := SecurityOptions{Roles: roles}
	assert.True(t, checkScopesAndRoles(nil, tokenRoles, opts, false), "roles should match")
}

func TestFailure_CheckScopesAndRoles_MissingScopesInToken(t *testing.T) {
	tokenScopes := []string{"profile"}
	tokenRoles := []string{"USER", "DEVELOPER"}
	scopes := []string{"profile", "email"}
	roles := []string{"USER", "DEVELOPER"}
	opts := SecurityOptions{Scopes: scopes, Roles: roles}
	assert.True(t, checkScopesAndRoles(tokenScopes, tokenRoles, opts, false), "scopes should match")
}

func TestFailure_CheckScopesAndRoles_StrictScopeValidation(t *testing.T) {
	tokenScopes := []string{"profile"}
	scopes := []string{"profile", "email"}
	opts := SecurityOptions{Scopes: scopes, StrictScopeValidation: true}
	assert.False(t, checkScopesAndRoles(tokenScopes, nil, opts, false), "scopes should not match")
}

func TestSuccess_CheckScopes_StrictValidation(t *testing.T) {
	tokenScopes := []string{"profile"}
	scopes := []string{"profile", "email"}
	opts := SecurityOptions{Scopes: scopes, StrictValidation: true}
	assert.True(t, checkScopesAndRoles(tokenScopes, nil, opts, false), "one of the scopes should match")
}

func TestSuccess_CheckScopesAndRoles_StrictValidation(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	scopes := []string{"profile", "email"}
	opts := SecurityOptions{Scopes: scopes, StrictValidation: true}
	assert.True(t, checkScopesAndRoles(tokenScopes, nil, opts, false), "scopes should match")
}

func TestFailure_CheckScopesAndRoles_NotAllRolesMatch(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	tokenRoles := []string{"USER"}
	scopes := []string{"profile", "email"}
	roles := []string{"USER", "DEVELOPER"}
	opts := SecurityOptions{Scopes: scopes, Roles: roles}
	assert.True(t, checkScopesAndRoles(tokenScopes, tokenRoles, opts, false), "roles should not match")
}

func TestFailure_CheckScopesAndRoles_IsAnynymousScopesMatchRolesIgnored(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	tokenRoles := []string{"USER"}
	scopes := []string{"profile", "email"}
	roles := []string{"DEVELOPER"}
	opts := SecurityOptions{Scopes: scopes, Roles: roles}
	assert.True(t, checkScopesAndRoles(tokenScopes, tokenRoles, opts, true), "roles should not match but still valid due to anonymous")
}

func TestFailure_CheckScopesAndRoles_IsAnynymousRolesIgnored(t *testing.T) {
	tokenRoles := []string{"USER"}
	roles := []string{"DEVELOPER"}
	opts := SecurityOptions{Roles: roles}
	assert.True(t, checkScopesAndRoles(nil, tokenRoles, opts, true), "roles should not match but still valid due to anonymous")
}

func TestSuccess_ContainsScopesSameArray(t *testing.T) {
	requestedData := []string{"TestScope", "openid", "profile"}
	tokenData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, requestedData)
	assert.True(t, isValid, "Requested scopes should be in tokenData")
}

func TestSuccess_ContainsScopesRequestedDataArrayWithLessItems(t *testing.T) {
	tokenData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, nil)
	assert.True(t, isValid, "Requested scopes should be in tokenData")
}

func TestSuccess_ContainsWithEmptyArray(t *testing.T) {
	tokenData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, []string{})
	assert.True(t, isValid, "Requested scopes should be in tokenData")
}

func TestSuccess_ContainsWithEmptyTokenData(t *testing.T) {
	requestData := []string{"TestScope", "openid", "profile"}
	isValid := contains(nil, requestData)
	assert.False(t, isValid)
}

func TestFailure_ContainsWithStrictValidation(t *testing.T) {
	tokenData := []string{"TestScope", "openid"}
	requestData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, requestData)
	assert.False(t, isValid)
}

func TestSuccess_ContainsWithStrictValidation(t *testing.T) {
	tokenData := []string{"TestScope", "openid", "profile"}
	requestData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, requestData)
	assert.True(t, isValid)
}

func TestFailure_ContainsNoMatch(t *testing.T) {
	tokenData := []string{"test", "scope", "user"}
	requestData := []string{"TestScope", "openid", "profile"}
	isValid := contains(tokenData, requestData)
	assert.False(t, isValid)
}

func TestSuccess_ContainsMatch(t *testing.T) {
	tokenData := []string{"test", "scope", "profile"}
	requestData := []string{"TestScope", "openid", "profile"}
	isValid := containsAny(tokenData, requestData)
	assert.True(t, isValid)
}

func TestSuccess_ContainsScopesRequestedDataArrayWithMoreItems(t *testing.T) {
	requestedData := []string{"TestScope", "openid", "profile", "email"}
	tokenData := []string{"TestScope", "openid", "profile"}
	isValid := containsAny(tokenData, requestedData)
	assert.True(t, isValid, "Requested scopes should be more than in tokenData")
}

func createToken(t *testing.T, pk *rsa.PrivateKey, issuer string, setExpired bool, keyID ...string) string {
	return createTokenWithScopesAndRoles(t, pk, issuer, setExpired, []string{"profile", "cidaas:compromissed_credentials"}, nil, keyID...)
}

func createTokenWithScopesAndRoles(t *testing.T, pk *rsa.PrivateKey, issuer string, setExpired bool, scopes []string, roles []string, keyID ...string) string {
	return createTokenWithScopesRolesSub(t, pk, issuer, setExpired, scopes, roles, "sub", keyID...)
}

func createTokenWithScopesRolesSub(t *testing.T, pk *rsa.PrivateKey, issuer string, setExpired bool, scopes []string, roles []string, sub string, keyID ...string) string {
	token := jwt.New(jwt.SigningMethodRS256)
	kid := "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	if len(keyID) != 0 {
		kid = keyID[0]
	}
	iss := "https://base.cidaas.de"
	if issuer != "" {
		iss = issuer
	}
	duration := 1000 * time.Second
	if setExpired {
		duration *= -1
	}
	token.Header["kid"] = kid
	registeredClaims := jwt.RegisteredClaims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  jwt.ClaimStrings{"clientTest"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        "7da05fac-0f79-4925-bb58-ab9602cb581f",
	}
	token.Claims = cidaasTokenClaims{Scopes: scopes, Roles: roles, RegisteredClaims: registeredClaims}
	if pk == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pk = key
	}
	s, err := token.SignedString(pk)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
