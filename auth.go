package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rootservices/auth/internal/logger"
	"github.com/rootservices/auth/internal/validate"
)

const (
	defaultForwardHeaderName = "X-Forward-IdToken"
	defaultRequired          = true
)

// Config the plugin configuration.
type Config struct {
	HeaderName        string `json:"headerName,omitempty"`
	Provider          string `json:"provider,omitempty"` // google, firebase
	Audience          string `json:"audience,omitempty"`
	ForwardHeaderName string `json:"forwardHeaderName,omitempty"`
	Required          *bool  `json:"required,omitempty"`
}

type AuthPlugin struct {
	next              http.Handler
	headerName        string
	name              string
	validator         validate.TokenValidator
	audience          string
	forwardHeaderName string
	required          bool
	logger            *logger.Log
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return NewAuthPlugin(ctx, next, config, name)
}

// New created a new Auth plugin.
func NewAuthPlugin(ctx context.Context, next http.Handler, config *Config, name string) (*AuthPlugin, error) {
	logger := logger.New("INFO", "")

	if config.Audience == "" {
		logger.Error("audience is required")
		return nil, fmt.Errorf("audience is required")
	}

	validator, err := validate.TokenValidatorFactory(ctx, validate.ValidatorType(config.Provider), logger)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create validator: %s", err))
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}

	forwardHeaderName := config.ForwardHeaderName
	if forwardHeaderName == "" {
		forwardHeaderName = defaultForwardHeaderName
	}
	required := defaultRequired
	if config.Required != nil {
		required = *config.Required
	}

	return &AuthPlugin{
		headerName:        config.HeaderName,
		next:              next,
		name:              name,
		validator:         validator,
		audience:          config.Audience,
		forwardHeaderName: forwardHeaderName,
		required:          required,
		logger:            logger,
	}, nil
}

func (auth *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token := req.Header.Get(auth.headerName)
	if token == "" && auth.required {
		auth.logger.Error("token is required")
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		return
	} else if token == "" && !auth.required {
		auth.logger.Debug("token is empty but not required")
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
		auth.logger.Debug("token is invalid but not required")
		auth.next.ServeHTTP(rw, req)
		return
	}

	req.Header.Set(auth.forwardHeaderName, token)
	auth.next.ServeHTTP(rw, req)
}
