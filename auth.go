package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rootservices/auth/internal/validate"
)

const defaultForwardHeaderName = "X-Forward-IdToken"

// Config the plugin configuration.
type Config struct {
	HeaderName        string `json:"headerName,omitempty"`
	Provider          string `json:"provider,omitempty"` // google, firebase
	Audience          string `json:"audience,omitempty"`
	ForwardHeaderName string `json:"forwardHeaderName,omitempty"`
	Required          bool   `json:"required,omitempty"`
}

type Auth struct {
	next              http.Handler
	headerName        string
	name              string
	validator         validate.TokenValidator
	audience          string
	forwardHeaderName string
	required          bool
}

// New created a new Auth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}

	validator, err := validate.TokenValidatorFactory(ctx, validate.ValidatorType(config.Provider))
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	forwardHeaderName := config.ForwardHeaderName
	if forwardHeaderName == "" {
		forwardHeaderName = defaultForwardHeaderName
	}

	return &Auth{
		headerName:        config.HeaderName,
		next:              next,
		name:              name,
		validator:         validator,
		audience:          config.Audience,
		forwardHeaderName: config.ForwardHeaderName,
		required:          config.Required,
	}, nil
}

func (auth *Auth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(auth.headerName)
	if token == "" && auth.required {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	} else if token == "" && !auth.required {
		auth.next.ServeHTTP(rw, req)
		return
	}

	// Remove Bearer prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	_, err := auth.validator.Verify(req.Context(), token, auth.audience)
	if err != nil && auth.required {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	} else if err != nil && !auth.required {
		auth.next.ServeHTTP(rw, req)
		return
	}

	req.Header.Set(auth.forwardHeaderName, token)
	auth.next.ServeHTTP(rw, req)
}
