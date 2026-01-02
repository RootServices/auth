package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoOp(t *testing.T) {
	cfg := CreateConfig()
	cfg.HeaderName = "foo"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}

func TestServeHTTP_TableDriven(t *testing.T) {
	tests := []struct {
		desc         string
		config       *Config
		expectedCode int
		expectedBody string
	}{
		{
			desc: "default config",
			config: &Config{
				HeaderName: "default-header",
			},
			expectedCode: http.StatusOK,
			expectedBody: "OK",
		},
		{
			desc: "empty header config",
			config: &Config{
				HeaderName: "",
			},
			expectedCode: http.StatusOK,
			expectedBody: "OK",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			ctx := context.Background()
			// Mock 'next' handler that writes a predictable response
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(test.expectedCode)
				_, _ = rw.Write([]byte(test.expectedBody))
			})

			handler, err := New(ctx, next, test.config, "test-plugin")
			if err != nil {
				t.Fatalf("failed to create plugin: %v", err)
			}

			recorder := httptest.NewRecorder()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			handler.ServeHTTP(recorder, req)

			if recorder.Code != test.expectedCode {
				t.Errorf("expected status code %d, got %d", test.expectedCode, recorder.Code)
			}

			if recorder.Body.String() != test.expectedBody {
				t.Errorf("expected body %q, got %q", test.expectedBody, recorder.Body.String())
			}
		})
	}
}
