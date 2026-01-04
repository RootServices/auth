package validate

import (
	"context"
)

// Claims represents the data associated with a token.
type Claims struct {
	Subject string `json:"sub"`
}

// TokenValidator verifies ID tokens.
type TokenValidator interface {
	Verify(ctx context.Context, token, audience string) (*Claims, error)
}
