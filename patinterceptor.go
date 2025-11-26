package cidaasinterceptor

import (
	"context"
	"log"
	"net/http"
	"strings"
)

// PatInterceptor to secure APIs based on OAuth 2.0 with PAT (Personal Access Token) support
// PAT tokens can only be validated via introspection API
type PatInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
}

// NewPatInterceptor returns a newly constructed PAT interceptor instance with the provided options
func NewPatInterceptor(opts Options) (*PatInterceptor, error) {
	cidaasEndpoints, _, err := newInterceptor(opts)
	if err != nil {
		return nil, err
	}
	return &PatInterceptor{
		Options:   opts,
		endpoints: cidaasEndpoints,
	}, nil
}

// VerifyTokenByIntrospect (check for exp time, issuer and scopes, roles and groups)
// using the accesspass-srv/pat/introspect endpoint
func (m *PatInterceptor) VerifyTokenByIntrospect(next http.Handler, apiOptions SecurityOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get token from auth header
		tokenString, err := getTokenFromAuthHeader(r)
		if err != nil { // error getting Token from auth header
			log.Printf("Error getting token from Header: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenData := m.introspectToken(tokenString, apiOptions)
		if tokenData == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		rWithTokenData := r.WithContext(context.WithValue(r.Context(), TokenDataKey, *tokenData))
		next.ServeHTTP(w, rWithTokenData)
	})
}

// introspectToken validates the token using introspection via accesspass-srv/pat/introspect endpoint
// Uses common introspectTokenWithEndpoint function from introspect.go
func (m *PatInterceptor) introspectToken(tokenString string, apiOptions SecurityOptions) *TokenData {
	// Construct the accesspass-srv/pat/introspect endpoint (PAT-specific endpoint)
	introspectEndpoint := strings.TrimSuffix(m.Options.BaseURI, "/") + "/accesspass-srv/pat/introspect"
	// Use common introspectTokenWithEndpoint with PAT-specific endpoint and token type hint
	return introspectTokenWithEndpoint(m.Options, introspectEndpoint, tokenString, apiOptions, "pat")
}
