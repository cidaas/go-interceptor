package cidaasinterceptor

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNewGrpcInterceptor(t *testing.T) {
	// Create mock server instead of using real CIDAAS instance
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()

	opts := Options{
		BaseURI:  uri, // Use mock server URL
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	if interceptor == nil {
		t.Fatal("Interceptor should not be nil")
	}

	if interceptor.Options.BaseURI != opts.BaseURI {
		t.Errorf("Expected BaseURI %s, got %s", opts.BaseURI, interceptor.Options.BaseURI)
	}
}

func TestNewGrpcInterceptor_Error(t *testing.T) {
	// Test with empty BaseURI
	opts := Options{
		BaseURI:  "",
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err == nil {
		t.Fatal("Expected error for empty BaseURI")
	}

	if interceptor != nil {
		t.Fatal("Interceptor should be nil on error")
	}
}

func TestGetTokenFromGrpcMetadata(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer test-token",
			expectError:   false,
			expectedToken: "test-token",
		},
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectError: true,
		},
		{
			name:        "invalid token format",
			authHeader:  "Invalid test-token",
			expectError: true,
		},
		{
			name:        "empty bearer token",
			authHeader:  "Bearer ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.authHeader != "" {
				md := metadata.New(map[string]string{
					"authorization": tt.authHeader,
				})
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			token, err := getTokenFromGrpcMetadata(ctx)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
				}
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer test-token",
			expectError:   false,
			expectedToken: "test-token",
		},
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectError: true,
		},
		{
			name:        "invalid token format",
			authHeader:  "Invalid test-token",
			expectError: true,
		},
		{
			name:        "empty bearer token",
			authHeader:  "Bearer ",
			expectError: true,
		},
		{
			name:        "case insensitive bearer",
			authHeader:  "bearer test-token",
			expectError: false,
			expectedToken: "test-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := extractBearerToken(tt.authHeader)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
				}
			}
		})
	}
}

func TestGetTokenDataFromGrpcContext(t *testing.T) {
	// Test with token data in context
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	retrievedTokenData, ok := GetTokenDataFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve token data from context")
	}

	if retrievedTokenData.Sub != tokenData.Sub {
		t.Errorf("Expected Sub %s, got %s", tokenData.Sub, retrievedTokenData.Sub)
	}

	if retrievedTokenData.Aud != tokenData.Aud {
		t.Errorf("Expected Aud %s, got %s", tokenData.Aud, retrievedTokenData.Aud)
	}

	// Test with no token data in context
	emptyCtx := context.Background()
	_, ok = GetTokenDataFromGrpcContext(emptyCtx)
	if ok {
		t.Error("Expected no token data to be found in empty context")
	}
}

func TestGetSubFromGrpcContext(t *testing.T) {
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	sub, ok := GetSubFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve sub from context")
	}

	if sub != tokenData.Sub {
		t.Errorf("Expected Sub %s, got %s", tokenData.Sub, sub)
	}
}

func TestGetAudFromGrpcContext(t *testing.T) {
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	aud, ok := GetAudFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve aud from context")
	}

	if aud != tokenData.Aud {
		t.Errorf("Expected Aud %s, got %s", tokenData.Aud, aud)
	}
}

// Mock handler for testing interceptors
func mockHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

func TestGrpcInterceptor_VerifyTokenByIntrospect_NoToken(t *testing.T) {
	// Create mock servers
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()

	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: true, Iss: uri})
	defer closeIntrospectSrv()

	opts := Options{
		BaseURI:  uri,
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	// Override endpoints to use mock introspect server
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}

	// Test without token
	ctx := context.Background()
	handler := interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}})
	
	_, err = handler(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Test/Test"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	})

	if err == nil {
		t.Fatal("Expected error for missing token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated, got %v", st.Code())
	}
}

func TestGrpcInterceptor_VerifyTokenByIntrospect_ValidToken(t *testing.T) {
	// Create mock servers
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()

	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: true, Iss: uri, Aud: "test-client", Sub: "test-user"})
	defer closeIntrospectSrv()

	opts := Options{
		BaseURI:  uri,
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	// Override endpoints to use mock introspect server
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}

	// Test with valid token
	ctx := context.Background()
	md := metadata.New(map[string]string{
		"authorization": "Bearer valid-token",
	})
	ctx = metadata.NewIncomingContext(ctx, md)

	handler := interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}})
	
	result, err := handler(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Test/Test"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		// Verify token data is in context
		tokenData, ok := GetTokenDataFromGrpcContext(ctx)
		if !ok {
			t.Fatal("Token data not found in context")
		}
		if tokenData.Sub != "test-user" {
			t.Errorf("Expected sub 'test-user', got %s", tokenData.Sub)
		}
		if tokenData.Aud != "test-client" {
			t.Errorf("Expected aud 'test-client', got %s", tokenData.Aud)
		}
		return "success", nil
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "success" {
		t.Errorf("Expected 'success', got %v", result)
	}
}

func TestGrpcInterceptor_VerifyTokenByIntrospect_InvalidToken(t *testing.T) {
	// Create mock servers
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()

	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: false})
	defer closeIntrospectSrv()

	opts := Options{
		BaseURI:  uri,
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	// Override endpoints to use mock introspect server
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}

	// Test with invalid token
	ctx := context.Background()
	md := metadata.New(map[string]string{
		"authorization": "Bearer invalid-token",
	})
	ctx = metadata.NewIncomingContext(ctx, md)

	handler := interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile"}})
	
	_, err = handler(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Test/Test"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	})

	if err == nil {
		t.Fatal("Expected error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated, got %v", st.Code())
	}
}

func TestGrpcInterceptor_VerifyTokenBySignature_ValidToken(t *testing.T) {
	// Create mock servers
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	defer close()

	// Create a valid token
	token := createToken(t, pk, uri, false)

	opts := Options{
		BaseURI:  uri,
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	// Override endpoints to use mock JWKS
	interceptor.endpoints = cidaasEndpoints{JwksURI: jwksURI}

	// Test with valid token
	ctx := context.Background()
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	ctx = metadata.NewIncomingContext(ctx, md)

	handler := interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile"}})
	
	result, err := handler(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Test/Test"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		// Verify token data is in context
		tokenData, ok := GetTokenDataFromGrpcContext(ctx)
		if !ok {
			t.Fatal("Token data not found in context")
		}
		if tokenData.Sub != "sub" {
			t.Errorf("Expected sub 'sub', got %s", tokenData.Sub)
		}
		if tokenData.Aud != "clientTest" {
			t.Errorf("Expected aud 'clientTest', got %s", tokenData.Aud)
		}
		return "success", nil
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "success" {
		t.Errorf("Expected 'success', got %v", result)
	}
}

func TestGrpcInterceptor_VerifyTokenBySignature_InvalidToken(t *testing.T) {
	// Create mock servers
	jwks, _ := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	defer close()

	opts := Options{
		BaseURI:  uri,
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	// Override endpoints to use mock JWKS
	interceptor.endpoints = cidaasEndpoints{JwksURI: jwksURI}

	// Test with invalid token
	ctx := context.Background()
	md := metadata.New(map[string]string{
		"authorization": "Bearer invalid-token",
	})
	ctx = metadata.NewIncomingContext(ctx, md)

	handler := interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile"}})
	
	_, err = handler(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Test/Test"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "success", nil
	})

	if err == nil {
		t.Fatal("Expected error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated, got %v", st.Code())
	}
}


