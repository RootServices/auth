package validate

import (
	"context"
	"fmt"
)

// ValidatorType represents the type of token validator to create.
type ValidatorType string

const (
	// GoogleValidatorType creates a validator that verifies Google ID tokens.
	GoogleValidatorType ValidatorType = "google"
	// FirebaseValidatorType creates a validator that verifies Firebase ID tokens.
	FirebaseValidatorType ValidatorType = "firebase"
)

// newFireBaseAuthClientFunc is a variable to allow mocking in tests.
var newFireBaseAuthClientFunc = NewFireBaseAuthClient

// TokenValidatorFactory creates a new TokenValidator based on the provided type.
// For FirebaseValidatorType, it attempts to create a FirebaseAuthClient using the provided context.
func TokenValidatorFactory(ctx context.Context, validatorType ValidatorType) (TokenValidator, error) {
	switch validatorType {
	case GoogleValidatorType:
		return NewGoogleTokenValidator(), nil
	case FirebaseValidatorType:
		client, err := newFireBaseAuthClientFunc(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create firebase client: %w", err)
		}
		return NewFirebaseTokenValidator(client), nil
	default:
		return nil, fmt.Errorf("unsupported validator type: %s", validatorType)
	}
}
