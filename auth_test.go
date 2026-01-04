package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rootservices/auth/internal/validate"
)

func boolPtr(b bool) *bool {
	return &b
}

// MockValidator to test ServeHTTP without relying on external services
type MockValidator struct {
	VerifyFunc func(ctx context.Context, token, audience string) (*validate.Claims, error)
}

func (m *MockValidator) Verify(ctx context.Context, token, audience string) (*validate.Claims, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, token, audience)
	}
	return nil, nil
}

func TestAuth_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		token          string
		required       bool
		mockVerify     func(ctx context.Context, token, audience string) (*validate.Claims, error)
		expectedStatus int
	}{
		{
			name: "valid token",
			config: &Config{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "valid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				return &validate.Claims{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid token with bearer prefix",
			config: &Config{
				HeaderName: "Authorization",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "Bearer valid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				if token != "valid-token" {
					t.Errorf("expected token %q, got %q", "valid-token", token)
				}
				return &validate.Claims{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing token",
			config: &Config{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			config: &Config{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "invalid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				return nil, fmt.Errorf("invalid token")
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "missing token but not required",
			config: &Config{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(false),
			},
			token: "",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid token but not required",
			config: &Config{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(false),
			},
			token: "invalid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*validate.Claims, error) {
				return nil, fmt.Errorf("invalid token")
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(http.StatusOK)
			})
			subject, err := NewAuthPlugin(context.Background(), next, tt.config, "test")
			if err != nil {
				t.Fatal(err)
			}

			subject.validator = &MockValidator{VerifyFunc: tt.mockVerify}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				req.Header.Set(tt.config.HeaderName, tt.token)
			}

			subject.ServeHTTP(recorder, req)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}
		})
	}
}

// These tests dont allow looking into defaults of AuthPlugin because the
// subject returned is a http.Handler.
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
				if err == nil {
					t.Error("expected error")
				}
				if handler != nil {
					t.Errorf("expected handler to be nil, got %v", handler)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if handler == nil {
					t.Error("expected handler to be not nil")
				}
			}
		})
	}
}

// These tests allow looking into defaults of AuthPlugin because the
// subject returned is a AuthPlugin.
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
				if err == nil {
					t.Error("expected error")
				}
				if subject != nil {
					t.Errorf("expected subject to be nil, got %v", subject)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if subject == nil {
					t.Error("expected subject to be not nil")
				} else {
					if tt.expectedForwardHeaderName != subject.forwardHeaderName {
						t.Errorf("expected forwardHeaderName %q, got %q", tt.expectedForwardHeaderName, subject.forwardHeaderName)
					}
					if tt.expectedRequired != subject.required {
						t.Errorf("expected required %v, got %v", tt.expectedRequired, subject.required)
					}
				}
			}
		})
	}
}
