package validate

import (
	"context"
	"fmt"

	"github.com/rootservices/auth/internal/logger"
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
func TokenValidatorFactory(ctx context.Context, validatorType ValidatorType, logger *logger.Log) (TokenValidator, error) {
	switch validatorType {
	case GoogleValidatorType:
		return NewGoogleTokenValidator(logger), nil
	case FirebaseValidatorType:
		client, err := newFireBaseAuthClientFunc(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create firebase client: %w", err)
		}
		return NewFirebaseTokenValidator(client, logger), nil
	default:
		logger.Error(fmt.Sprintf("unsupported validator type: %s", validatorType))
		return nil, fmt.Errorf("unsupported validator type: %s", validatorType)
	}
}
