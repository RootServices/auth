package validate

import (
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

// NewTokenValidator creates a new TokenValidator based on the provided type.
// For FirebaseValidatorType, a non-nil firebaseClient is required.
func NewTokenValidator(validatorType ValidatorType, firebaseClient FirebaseAuthClient) (TokenValidator, error) {
	switch validatorType {
	case GoogleValidatorType:
		return NewGoogleTokenValidator(), nil
	case FirebaseValidatorType:
		if firebaseClient == nil {
			return nil, fmt.Errorf("firebase client is required for firebase validator")
		}
		return NewFirebaseTokenValidator(firebaseClient), nil
	default:
		return nil, fmt.Errorf("unsupported validator type: %s", validatorType)
	}
}
