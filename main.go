package auth

import (
	"context"
	"net/http"

	plugin "github.com/rootservices/auth/internal"
)

func boolPtr(b bool) *bool {
	return &b
}

// Config the plugin configuration.
// Required by Traefik
type Config struct {
	HeaderName        string `json:"headerName,omitempty"`
	Provider          string `json:"provider,omitempty"` // google, firebase
	Audience          string `json:"audience,omitempty"`
	ForwardHeaderName string `json:"forwardHeaderName,omitempty"`
	Required          *bool  `json:"required,omitempty"`
}

// called by traefik
func CreateConfig() *Config {
	return &Config{
		HeaderName:        "Authorization",
		Provider:          "google",
		Audience:          "audience-that-must-match",
		ForwardHeaderName: "X-Forward-IdToken",
		Required:          boolPtr(true),
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	input := &plugin.PluginInput{
		HeaderName:        config.HeaderName,
		Provider:          config.Provider,
		Audience:          config.Audience,
		ForwardHeaderName: config.ForwardHeaderName,
		Required:          config.Required,
	}
	return plugin.NewAuthPlugin(ctx, next, input, name)
}
