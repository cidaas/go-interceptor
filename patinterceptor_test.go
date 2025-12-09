package cidaasinterceptor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const introspectionPath = "/accesspass-srv/passes/pat/introspect"

func TestNewPatInterceptor_Error(t *testing.T) {
	interceptor, err := NewPatInterceptor(Options{})
	assert.Error(t, err)
	assert.Nil(t, interceptor)
}

func TestNewPatInterceptor_Success(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := NewPatInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
}

func TestPatInterceptor_IntrospectHandler_NoToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
	res := doFiberRequest(t, "", interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestPatInterceptor_IntrospectHandler_InvalidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := "test-token"
	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createPatIntrospectMockServer(introspectResponse{Active: false}, uri)
	defer closeIntrospectSrv()
	// Override BaseURI to point to mock server for testing
	interceptor.Options.BaseURI = introspectURI
	res := doFiberRequest(t, token, interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestPatInterceptor_IntrospectHandler_ValidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := "test-pat-token"
	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createPatIntrospectMockServer(introspectResponse{Active: true, Aud: "clientTest", Sub: "sub"}, uri)
	defer closeIntrospectSrv()
	// Override BaseURI to point to mock server for testing
	interceptor.Options.BaseURI = introspectURI
	res := doFiberRequest(t, token, interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}}))
	assert.Equal(t, http.StatusOK, res.StatusCode)
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, res.StatusCode, "handler should return 200 status code")
}

func TestPatInterceptor_IntrospectHandler_IssuerMismatch(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := "test-pat-token"
	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc(introspectionPath, func(w http.ResponseWriter, r *http.Request) {
		// Return a response with a different issuer to test issuer mismatch
		json.NewEncoder(w).Encode(introspectResponse{Active: true, Iss: "other-issuer", Aud: "clientTest", Sub: "sub"})
	})
	mockServer = httptest.NewServer(mockHandler)
	defer mockServer.Close()
	// Override BaseURI to point to mock server for testing
	interceptor.Options.BaseURI = mockServer.URL
	res := doFiberRequest(t, token, interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestPatInterceptor_VerifyPassedData(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	secOpts := SecurityOptions{
		Roles:                 []string{"role1"},
		Scopes:                []string{"scope1"},
		Groups:                []GroupValidationOptions{{GroupID: "groupID"}},
		StrictGroupValidation: true,
		StrictScopeValidation: false,
		StrictRoleValidation:  true,
		StrictValidation:      true,
	}
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc(introspectionPath, func(w http.ResponseWriter, r *http.Request) {
		req := &introspectRequest{}
		json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
		assert.Equal(t, secOpts.Roles, req.Roles)
		assert.Equal(t, secOpts.Scopes, req.Scopes)
		assert.Equal(t, secOpts.Groups, req.Groups)
		assert.Equal(t, secOpts.StrictGroupValidation, req.StrictGroupValidation)
		assert.Equal(t, secOpts.StrictRoleValidation, req.StrictRoleValidation)
		assert.Equal(t, secOpts.StrictScopeValidation, req.StrictScopeValidation)
		assert.Equal(t, secOpts.StrictValidation, req.StrictValidation)
		assert.Equal(t, "test-pat-token", req.Token)
		assert.Equal(t, "clientID", req.ClientID)
		assert.Equal(t, "pat", req.TokenTypeHint, "TokenTypeHint should be 'pat' for PAT interceptor")
		json.NewEncoder(w).Encode(introspectResponse{Active: true, Aud: "clientID", Sub: "sub", Iss: mockServer.URL})
	})
	mockServer = httptest.NewServer(mockHandler)
	defer mockServer.Close()

	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true, ClientID: "clientID"})
	assert.NoError(t, err)
	// Override BaseURI to point to mock server for testing
	interceptor.Options.BaseURI = mockServer.URL
	res := doFiberRequest(t, "test-pat-token", interceptor.VerifyTokenByIntrospect(secOpts))
	assert.Equal(t, http.StatusOK, res.StatusCode)
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "sub", tokenData.Sub)
	assert.Equal(t, "clientID", tokenData.Aud)
}

func TestPatInterceptor_UsesAccessPassEndpoint(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	var calledEndpoint string
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc(introspectionPath, func(w http.ResponseWriter, r *http.Request) {
		calledEndpoint = r.URL.Path
		json.NewEncoder(w).Encode(introspectResponse{Active: true, Aud: "clientID", Sub: "sub", Iss: mockServer.URL})
	})
	mockServer = httptest.NewServer(mockHandler)
	defer mockServer.Close()

	interceptor, err := NewPatInterceptor(Options{BaseURI: uri, Debug: true, ClientID: "clientID"})
	assert.NoError(t, err)
	// Override BaseURI to point to mock server for testing
	interceptor.Options.BaseURI = mockServer.URL
	res := doFiberRequest(t, "test-pat-token", interceptor.VerifyTokenByIntrospect(SecurityOptions{}))
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, introspectionPath, calledEndpoint, "Should call "+introspectionPath+" endpoint")
}

// createPatIntrospectMockServer creates a mock server for PAT introspection endpoint
func createPatIntrospectMockServer(res introspectResponse, expectedBaseURI string) (string, func()) {
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc(introspectionPath, func(w http.ResponseWriter, r *http.Request) {
		// Always set issuer to mockServer.URL so it matches when BaseURI is overridden
		res.Iss = mockServer.URL
		json.NewEncoder(w).Encode(res)
	})
	mockServer = httptest.NewServer(mockHandler)
	return mockServer.URL, func() { mockServer.Close() }
}
