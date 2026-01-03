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

func boolPtr(b bool) *bool {
	return &b
}

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
			authPlugin := &AuthPlugin{
				next: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
				}),
				headerName: tt.headerName,
				validator:  validator,
				required:   tt.required,
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

// These blocks allow looking into defaults because the subject returned is a http.Handler.
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

// These allow looking into defaults because the subject returned is a AuthPlugin.
func TestNewAuthPlugin(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	tests := []struct {
		name                      string
		config                    *Config
		expectedForwardHeaderName string
		expectedRequired          bool
		expectError               bool
	}{
		{
			name: "google provider should use default values",
			config: &Config{
				HeaderName: "Authorization",
				Provider:   "google",
				Audience:   "gateway-audience",
			},
			expectedForwardHeaderName: defaultForwardHeaderName,
			expectedRequired:          defaultRequired,
			expectError:               false,
		},
		{
			name: "google provider should assign forward header name and required",
			config: &Config{
				HeaderName:        "Authorization",
				Provider:          "google",
				Audience:          "gateway-audience",
				ForwardHeaderName: "X-Forward-IdToken-Test",
				Required:          boolPtr(false),
			},
			expectedForwardHeaderName: "X-Forward-IdToken-Test",
			expectedRequired:          false,
			expectError:               false,
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
			subject, err := NewAuthPlugin(ctx, next, tt.config, "test")
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, subject)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, subject)
				assert.Equal(t, tt.expectedForwardHeaderName, subject.forwardHeaderName)
				assert.Equal(t, tt.expectedRequired, subject.required)
			}
		})
	}
}
