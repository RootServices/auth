package plugin

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/idtoken"
)

// -- Mocks --

type mockHeader struct {
	headers map[string][]string
}

func newMockHeader() *mockHeader {
	return &mockHeader{headers: make(map[string][]string)}
}

func (h *mockHeader) Names() []string {
	keys := make([]string, 0, len(h.headers))
	for k := range h.headers {
		keys = append(keys, k)
	}
	return keys
}

func (h *mockHeader) Get(name string) (string, bool) {
	if v, ok := h.headers[name]; ok && len(v) > 0 {
		return v[0], true
	}
	return "", false
}

func (h *mockHeader) GetAll(name string) []string {
	return h.headers[name]
}

func (h *mockHeader) Set(name, value string) {
	h.headers[name] = []string{value}
}

func (h *mockHeader) Add(name, value string) {
	h.headers[name] = append(h.headers[name], value)
}

func (h *mockHeader) Remove(name string) {
	delete(h.headers, name)
}

type mockBody struct{}

func (b *mockBody) WriteTo(w io.Writer) (uint64, error) { return 0, nil }
func (b *mockBody) Read(p []byte) (uint32, bool)        { return 0, true }
func (b *mockBody) Write(p []byte)                      {}
func (b *mockBody) WriteString(s string)                {}

type mockRequest struct {
	headers *mockHeader
}

func (r *mockRequest) GetMethod() string          { return "GET" }
func (r *mockRequest) SetMethod(string)           {}
func (r *mockRequest) GetURI() string             { return "/" }
func (r *mockRequest) SetURI(string)              {}
func (r *mockRequest) GetProtocolVersion() string { return "HTTP/1.1" }
func (r *mockRequest) Headers() api.Header        { return r.headers }
func (r *mockRequest) GetSourceAddr() string      { return "127.0.0.1" }
func (r *mockRequest) Body() api.Body             { return &mockBody{} }
func (r *mockRequest) Trailers() api.Header       { return &mockHeader{} }

type mockResponse struct {
	statusCode uint32
	headers    *mockHeader
}

func (r *mockResponse) GetStatusCode() uint32  { return r.statusCode }
func (r *mockResponse) SetStatusCode(c uint32) { r.statusCode = c }
func (r *mockResponse) Headers() api.Header    { return r.headers }
func (r *mockResponse) Body() api.Body         { return &mockBody{} }
func (r *mockResponse) Trailers() api.Header   { return &mockHeader{} }

// MockCtx implements api.Ctx and context.Context
type MockCtx struct {
	context.Context
}

// Next is only in recent api? Let's check definitions. api.Ctx definition in api.go doesn't force Next?
// In api.go: context.Context. type Ctx interface { context.Context }
// So MockCtx as struct embedding context.Context is enough.

// MockValidator
type MockValidator struct {
	VerifyFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
}

func (m *MockValidator) Verify(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	return m.VerifyFunc(ctx, token, audience)
}

func boolPtr(b bool) *bool { return &b }

func TestAuthPlugin_HandleRequest(t *testing.T) {
	tests := []struct {
		name           string
		config         *PluginInput
		token          string
		required       bool
		mockVerify     func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
		expectedStatus uint32
		expectedNext   bool
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
			expectedStatus: 0, // 0 means not set (OK)
			expectedNext:   true,
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
			expectedStatus: 0,
			expectedNext:   true,
		},
		{
			name: "missing token required",
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
			expectedStatus: 401,
			expectedNext:   false, // Should verify HandleRequest implementation checks return value
		},
		{
			name: "missing token not required",
			config: &PluginInput{
				HeaderName: "X-Auth-Token",
				Provider:   "google",
				Audience:   "gateway-audience",
				Required:   boolPtr(false),
			},
			token: "",
			mockVerify: func(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
				return nil, nil
			},
			expectedStatus: 0,
			expectedNext:   true,
		},
		{
			name: "invalid token required",
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
			expectedStatus: 401,
			expectedNext:   false, // Should not proceed
		},
		{
			name: "invalid token not required",
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
			expectedStatus: 0,
			expectedNext:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin, err := NewAuthPlugin(context.Background(), tt.config)
			if err != nil {
				// We expect success for google provider in setup unless config invalid
				assert.NoError(t, err)
			}
			plugin.validator = &MockValidator{VerifyFunc: tt.mockVerify}

			reqHeaders := newMockHeader()
			if tt.token != "" {
				reqHeaders.Set(tt.config.HeaderName, tt.token)
			}
			req := &mockRequest{headers: reqHeaders}
			resp := &mockResponse{headers: newMockHeader()}

			next, reqCtx := plugin.HandleRequest(req, resp)

			assert.Equal(t, tt.expectedNext, next)
			assert.Equal(t, uint32(0), reqCtx) // We always return 0 for now
			assert.Equal(t, tt.expectedStatus, resp.statusCode)
		})
	}
}
