package cidaasinterceptor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GrpcTokenDataKey key to access the token data in gRPC context
const GrpcTokenDataKey = "grpc_tokendata"

// GrpcInterceptor to secure gRPC APIs based on OAuth 2.0
type GrpcInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
	jwks      Jwks
}

// NewGrpcInterceptor returns a newly constructed gRPC interceptor instance with the provided options
func NewGrpcInterceptor(opts Options) (*GrpcInterceptor, error) {
	cidaasEndpoints, keys, err := newInterceptor(opts)
	if err != nil {
		return nil, err
	}
	return &GrpcInterceptor{
		Options:   opts,
		endpoints: cidaasEndpoints,
		jwks:      keys,
	}, nil
}

// VerifyTokenBySignature returns a gRPC unary interceptor that validates tokens by signature
func (m *GrpcInterceptor) VerifyTokenBySignature(apiOptions SecurityOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := getTokenFromGrpcMetadata(ctx)
		if err != nil {
			log.Printf("Error getting token from gRPC metadata: %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "unauthorized: %v", err)
		}

		tokenData := m.verifySignature(tokenString, apiOptions)
		if tokenData == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Add token data to gRPC context
		ctxWithTokenData := context.WithValue(ctx, GrpcTokenDataKey, *tokenData)
		return handler(ctxWithTokenData, req)
	}
}

// VerifyTokenByIntrospect returns a gRPC unary interceptor that validates tokens by introspection
func (m *GrpcInterceptor) VerifyTokenByIntrospect(apiOptions SecurityOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := getTokenFromGrpcMetadata(ctx)
		if err != nil {
			log.Printf("Error getting token from gRPC metadata: %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "unauthorized: %v", err)
		}

		tokenData := m.introspectToken(tokenString, apiOptions)
		if tokenData == nil {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// Add token data to gRPC context
		ctxWithTokenData := context.WithValue(ctx, GrpcTokenDataKey, *tokenData)
		return handler(ctxWithTokenData, req)
	}
}

// VerifyTokenBySignatureWithEndpointValidation returns a gRPC unary interceptor that validates tokens by signature
// with per-endpoint security options
func (m *GrpcInterceptor) VerifyTokenBySignatureWithEndpointValidation(endpointSecurity func(string) SecurityOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := getTokenFromGrpcMetadata(ctx)
		if err != nil {
			log.Printf("Error getting token from gRPC metadata: %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "unauthorized: %v", err)
		}

		// Get security options for this specific endpoint
		apiOptions := endpointSecurity(info.FullMethod)

		tokenData := m.verifySignature(tokenString, apiOptions)
		if tokenData == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Add token data to gRPC context
		ctxWithTokenData := context.WithValue(ctx, GrpcTokenDataKey, *tokenData)
		return handler(ctxWithTokenData, req)
	}
}

// VerifyTokenByIntrospectWithEndpointValidation returns a gRPC unary interceptor that validates tokens by introspection
// with per-endpoint security options
func (m *GrpcInterceptor) VerifyTokenByIntrospectWithEndpointValidation(endpointSecurity func(string) SecurityOptions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := getTokenFromGrpcMetadata(ctx)
		if err != nil {
			log.Printf("Error getting token from gRPC metadata: %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "unauthorized: %v", err)
		}

		// Get security options for this specific endpoint
		apiOptions := endpointSecurity(info.FullMethod)

		tokenData := m.introspectToken(tokenString, apiOptions)
		if tokenData == nil {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		// Add token data to gRPC context
		ctxWithTokenData := context.WithValue(ctx, GrpcTokenDataKey, *tokenData)
		return handler(ctxWithTokenData, req)
	}
}

// getTokenFromGrpcMetadata extracts the token from gRPC metadata
func getTokenFromGrpcMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata provided")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", errors.New("missing authorization header")
	}

	// Use the same token extraction logic as HTTP
	return extractBearerToken(authHeaders[0])
}

// extractBearerToken extracts the bearer token from the authorization header
func extractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("empty authorization header")
	}

	// Remove bearer in the authorization header
	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("invalid token - not of type: Bearer")
	}

	return authHeaderParts[1], nil
}

// GetTokenDataFromGrpcContext retrieves token data from gRPC context
func GetTokenDataFromGrpcContext(ctx context.Context) (*TokenData, bool) {
	tokenData, ok := ctx.Value(GrpcTokenDataKey).(TokenData)
	if !ok {
		return nil, false
	}
	return &tokenData, true
}

// GetSubFromGrpcContext retrieves the subject (sub) from gRPC context
func GetSubFromGrpcContext(ctx context.Context) (string, bool) {
	tokenData, ok := GetTokenDataFromGrpcContext(ctx)
	if !ok {
		return "", false
	}
	return tokenData.Sub, true
}

// GetAudFromGrpcContext retrieves the audience (aud) from gRPC context
func GetAudFromGrpcContext(ctx context.Context) (string, bool) {
	tokenData, ok := GetTokenDataFromGrpcContext(ctx)
	if !ok {
		return "", false
	}
	return tokenData.Aud, true
}

// verifySignature validates the token using signature verification
func (m *GrpcInterceptor) verifySignature(tokenString string, apiOptions SecurityOptions) *TokenData {
	// parse token
	token, err := jwt.ParseWithClaims(tokenString, &cidaasTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		pem, err := getKey(token, m.jwks)
		if err != nil {
			log.Printf("Reloading keys for Kid : %v", token.Header["kid"])
			keys, err := getKeys(m.endpoints.JwksURI)
			if err != nil {
				return nil, err
			}
			m.jwks = keys
			pem, err := getKey(token, m.jwks)
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
		if m.Options.Debug {
			log.Printf("Scopes: %v", claims.Scopes)
			log.Printf("Roles: %v", claims.Roles)
			log.Printf("Sub: %v", claims.Subject)
		}
		// check if sub is anonymous if not allowed
		isAnonymous := strings.EqualFold(claims.Subject, anonymousSub)
		if !apiOptions.AllowAnonymousSub && isAnonymous {
			return nil
		}
		// verify exp times in token data based on current timestamp
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			log.Printf("Token expired!, expiration: %v, now: %v", claims.ExpiresAt, time.Now())
			return nil
		}
		// verify issuer in token data based on baseURI given in options of interceptor
		if claims.Issuer != m.Options.BaseURI {
			log.Printf("Issuer mismatch, issuer: %v, base URI: %v", claims.Issuer, m.Options.BaseURI)
			return nil
		}

		// check for roles and scopes in token data
		if !checkScopesAndRoles(claims.Scopes, claims.Roles, apiOptions, isAnonymous) {
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

// introspectToken validates the token using introspection
func (m *GrpcInterceptor) introspectToken(tokenString string, apiOptions SecurityOptions) *TokenData {
	introspectReq := introspectRequest{
		Token:                 tokenString,
		TokenTypeHint:         "access_token",
		ClientID:              m.Options.ClientID,
		Roles:                 apiOptions.Roles,
		Scopes:                apiOptions.Scopes,
		Groups:                apiOptions.Groups,
		StrictRoleValidation:  apiOptions.StrictRoleValidation,
		StrictScopeValidation: apiOptions.StrictScopeValidation,
		StrictGroupValidation: apiOptions.StrictGroupValidation,
		StrictValidation:      apiOptions.StrictValidation,
	}
	// marshal token to introspect request and perform POST call to introspect endpoint
	introspectReqBody, err := json.Marshal(introspectReq)
	if err != nil {
		log.Printf("Error mapping introspect request: %v", err)
		return nil
	}
	if m.Options.Debug {
		log.Printf("IntrospectReqBody: %v", string(introspectReqBody))
	}
	// if introspect was not successful log error and return unauthorized
	resp, err := http.Post(m.endpoints.IntrospectionEndpoint, "application/json", bytes.NewBuffer(introspectReqBody))
	if err != nil {
		log.Printf("Error calling introspect: %v", err)
		return nil
	}
	defer resp.Body.Close()
	// map introspect call response (decode)
	var introspectRespBody introspectResponse
	errDec := json.NewDecoder(resp.Body).Decode(&introspectRespBody)
	if errDec != nil {
		log.Printf("Error mapping introspect Response: %v", err)
		return nil
	}
	if m.Options.Debug {
		log.Printf("IntrospectRespBody: %v", introspectRespBody)
	}
	// check if token is active, if not return unauthorized, root cause could be that token is expired or revoked
	if !introspectRespBody.Active {
		log.Printf("Token Expired/Revoked: Token.Active: %v", introspectRespBody.Active)
		return nil
	}
	// check for issuer in token data
	if introspectRespBody.Iss != m.Options.BaseURI {
		log.Println("Issuer mismatch")
		return nil
	}
	return &TokenData{Sub: introspectRespBody.Sub, Aud: introspectRespBody.Aud}
}
