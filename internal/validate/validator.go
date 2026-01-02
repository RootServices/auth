package validate

import (
	"context"

	"google.golang.org/api/idtoken"
)

// TokenValidator verifies ID tokens.
type TokenValidator interface {
	Verify(ctx context.Context, token, audience string) (*idtoken.Payload, error)
}
