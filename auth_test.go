package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/idtoken"
)

// MockValidator to test ServeHTTP without relying on external services
type MockValidator struct {
	VerifyFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
}

func (m *MockValidator) Verify(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, token, audience)
	}
	return nil, nil
}

func TestAuth_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		headerName     string
		tokenHeader    string
		required       bool
		mockVerify     func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
		expectedStatus int
	}{
		{
			name:        "valid token",
			headerName:  "X-Auth-Token",
			tokenHeader: "valid-token",
			required:    true,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "valid token with bearer prefix",
			headerName:  "Authorization",
			tokenHeader: "Bearer valid-token",
			required:    true,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				assert.Equal(t, "valid-token", token)
				return &idtoken.Payload{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "missing token",
			headerName:  "X-Auth-Token",
			tokenHeader: "",
			required:    true,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:        "invalid token",
			headerName:  "X-Auth-Token",
			tokenHeader: "invalid-token",
			required:    true,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, fmt.Errorf("invalid token")
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:        "missing token but not required",
			headerName:  "X-Auth-Token",
			tokenHeader: "",
			required:    false,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "invalid token but not required",
			headerName:  "X-Auth-Token",
			tokenHeader: "invalid-token",
			required:    false,
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, fmt.Errorf("invalid token")
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock validator
			validator := &MockValidator{VerifyFunc: tt.mockVerify}

			// Create the Auth handler manually with the mock validator
			authPlugin := &Auth{
				next: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
				}),
				headerName: tt.headerName,
				required:   tt.required,
				validator:  validator,
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.tokenHeader != "" {
				req.Header.Set(tt.headerName, tt.tokenHeader)
			}

			authPlugin.ServeHTTP(recorder, req)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
		})
	}
}

// TestNew verifies the New function logic (factory integration)
// This is harder to test fully without mocking the factory or having credentials.
// We can test the error cases or the Google case if it doesn't strictly checking creds on creation (it might not).
// validate.NewGoogleTokenValidator() just returns a struct, it doesn't call external services yet.
func TestNew(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "google provider",
			config: &Config{
				HeaderName: "Authorization",
				Provider:   "google",
				Audience:   "gateway-audience",
			},
			expectError: false,
		},
		{
			name: "Audience is missing",
			config: &Config{
				HeaderName: "Authorization",
				Provider:   "google",
			},
			expectError: true,
		},
		{
			name: "unknown provider",
			config: &Config{
				HeaderName: "Authorization",
				Provider:   "unknown",
				Audience:   "gateway-audience",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := New(ctx, next, tt.config, "test")
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, handler)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}
