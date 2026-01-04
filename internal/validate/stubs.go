//go:build yaegi
// +build yaegi

package validate

import (
	"context"
	"fmt"

	"github.com/rootservices/auth/internal/logger"
)

// GoogleTokenValidator Stub
type GoogleTokenValidator struct {
	logger *logger.Log
}

func NewGoogleTokenValidator(logger *logger.Log) *GoogleTokenValidator {
	return &GoogleTokenValidator{logger: logger}
}

func (v *GoogleTokenValidator) Verify(ctx context.Context, token, audience string) (*Claims, error) {
	return nil, fmt.Errorf("stub validator called in yaegi")
}

// FirebaseAuthClient Stub
type FirebaseAuthClient interface{}

// Firebase Stub
type FirebaseTokenValidator struct {
	logger *logger.Log
}

func NewFirebaseTokenValidator(client FirebaseAuthClient, logger *logger.Log) *FirebaseTokenValidator {
	return &FirebaseTokenValidator{logger: logger}
}

func NewFireBaseAuthClient(ctx context.Context) (FirebaseAuthClient, error) {
	return nil, nil
}

func (v *FirebaseTokenValidator) Verify(ctx context.Context, token, audience string) (*Claims, error) {
	return nil, fmt.Errorf("stub validator called in yaegi")
}
