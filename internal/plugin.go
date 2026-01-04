package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/rootservices/auth/internal/logger"
	"github.com/rootservices/auth/internal/validate"
)

const (
	defaultForwardHeaderName = "X-Forward-IdToken"
	defaultRequired          = true
)

type PluginInput struct {
	HeaderName        string `json:"headerName,omitempty"`
	Provider          string `json:"provider,omitempty"` // google, firebase
	Audience          string `json:"audience,omitempty"`
	ForwardHeaderName string `json:"forwardHeaderName,omitempty"`
	Required          *bool  `json:"required,omitempty"`
}

type AuthPlugin struct {
	headerName        string
	validator         validate.TokenValidator
	audience          string
	forwardHeaderName string
	required          bool
	logger            *logger.Log
}

// NewAuthPlugin created a new Auth plugin.
func NewAuthPlugin(ctx context.Context, config *PluginInput) (*AuthPlugin, error) {
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
		validator:         validator,
		audience:          config.Audience,
		forwardHeaderName: forwardHeaderName,
		required:          required,
		logger:            logger,
	}, nil
}

func (auth *AuthPlugin) HandleRequest(req api.Request, resp api.Response) (bool, uint32) {
	token, ok := req.Headers().Get(auth.headerName)
	if (!ok || token == "") && auth.required {
		auth.logger.Error("token is required")
		resp.SetStatusCode(401)
		resp.Body().WriteString("Unauthorized")
		return false, 0
	} else if (!ok || token == "") && !auth.required {
		auth.logger.Debug("token is empty but not required")
		return true, 0
	}

	// Remove Bearer prefix if present
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	// Use context.Background() as api.Request does not provide a context in this version.
	_, err := auth.validator.Verify(context.Background(), token, auth.audience)
	if err != nil && auth.required {
		auth.logger.Error(fmt.Sprintf("token verification failed: %v", err))
		resp.SetStatusCode(401)
		resp.Body().WriteString("Unauthorized")
		return false, 0
	} else if err != nil && !auth.required {
		auth.logger.Debug("token is invalid but not required")
		return true, 0
	}

	req.Headers().Set(auth.forwardHeaderName, token)
	return true, 0
}
