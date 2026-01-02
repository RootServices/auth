package validate

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

// GoogleTokenValidator implements TokenValidator for Google ID tokens.
type GoogleTokenValidator struct {
	// validatorFunc allows mocking the idtoken.Validate function for testing.
	validatorFunc func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error)
}

// NewGoogleTokenValidator creates a new GoogleTokenValidator.
func NewGoogleTokenValidator() *GoogleTokenValidator {
	return &GoogleTokenValidator{
		validatorFunc: idtoken.Validate,
	}
}

// Verify validates the given ID token.
func (validator *GoogleTokenValidator) Verify(ctx context.Context, token, audience string) (*idtoken.Payload, error) {
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}
	payload, err := validator.validatorFunc(ctx, token, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	return payload, nil
}
