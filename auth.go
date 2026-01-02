package auth

import (
	"context"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	HeaderName string `json:"headerName,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		HeaderName: "X-Traefik-NoOp",
	}
}

// NoOp a no-op plugin.
type NoOp struct {
	next       http.Handler
	headerName string
	name       string
}

// New created a new NoOp plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &NoOp{
		headerName: config.HeaderName,
		next:       next,
		name:       name,
	}, nil
}

func (e *NoOp) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	e.next.ServeHTTP(rw, req)
}
