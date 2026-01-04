package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	plugin "github.com/rootservices/auth/internal"
)

type Config struct {
	headerName        string `json:"headerName,omitempty"`
	provider          string `json:"provider,omitempty"` // google, firebase
	audience          string `json:"audience,omitempty"`
	forwardHeaderName string `json:"forwardHeaderName,omitempty"`
	required          *bool  `json:"required,omitempty"`
}

func init() {
	var config Config
	err := json.Unmarshal(handler.Host.GetConfig(), &config)
	if err != nil {
		handler.Host.Log(api.LogLevelError, fmt.Sprintf("Could not load config %v", err))
		os.Exit(1)
	}

	input := plugin.PluginInput{
		HeaderName:        config.headerName,
		Provider:          config.provider,
		Audience:          config.audience,
		ForwardHeaderName: config.forwardHeaderName,
		Required:          config.required,
	}

	plugin, err := plugin.NewAuthPlugin(context.Background(), &input)
	if err != nil {
		handler.Host.Log(api.LogLevelError, "failed to create auth plugin")
		os.Exit(1)
	}
	handler.HandleRequestFn = plugin.HandleRequest
}
