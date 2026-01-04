package plugin

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
		config         *PluginInput
		token          string
		required       bool
		mockVerify     func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
		expectedStatus int
	}{
		{
			name: "valid token",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "valid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "valid token with bearer prefix",
			config: &PluginInput{
				HeaderName: "Authorization",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "Bearer valid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				assert.Equal(t, "valid-token", token)
				return &idtoken.Payload{Subject: "user1"}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing token",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(true),
			},
			token: "invalid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, fmt.Errorf("invalid token")
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "missing token but not required",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(false),
			},
			token: "",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, nil // Should not be called
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid token but not required",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(false),
			},
			token: "invalid-token",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
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
				// We expect NewAuthPlugin to succeed for "google" provider if it doesn't do deep init checks that fail
				// If it fails, we might need to mock TokenValidatorFactory or use a noop provider?
				// Since we are moving code, we assume it behaves same as existing main_test.go
				t.Fatal(err)
			}

			// Inject mock validator
			subject.validator = &MockValidator{VerifyFunc: tt.mockVerify}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				req.Header.Set(tt.config.HeaderName, tt.token)
			}

			subject.ServeHTTP(recorder, req)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
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
		config      *PluginInput
		expectError bool
	}{
		{
			name: "google provider",
			config: &PluginInput{
				HeaderName: "Authorization",
				Provider:   "google",
				Audience:   "gateway-audience",
			},
			expectError: false,
		},
		{
			name: "Audience is missing",
			config: &PluginInput{
				HeaderName: "Authorization",
				Provider:   "google",
			},
			expectError: true,
		},
		{
			name: "unknown provider",
			config: &PluginInput{
				HeaderName: "Authorization",
				Provider:   "unknown",
				Audience:   "gateway-audience",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := NewAuthPlugin(ctx, next, tt.config, "test")
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

// These tests allow looking into defaults of AuthPlugin because the
// subject returned is a AuthPlugin.
func TestNewAuthPlugin(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	tests := []struct {
		name                      string
		config                    *PluginInput
		expectedForwardHeaderName string
		expectedRequired          bool
		expectError               bool
	}{
		{
			name: "google provider should use default values",
			config: &PluginInput{
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
			config: &PluginInput{
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
			config: &PluginInput{
				HeaderName: "Authorization",
				Provider:   "google",
			},
			expectError: true,
		},
		{
			name: "unknown provider",
			config: &PluginInput{
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
