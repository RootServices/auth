package validate

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/rootservices/auth/internal/logger"
	"google.golang.org/api/idtoken"
)

// FirebaseAuthClient defines the interface for verifying ID tokens.
// It is satisfied by *auth.Client.
type FirebaseAuthClient interface {
	VerifyIDTokenAndCheckRevoked(ctx context.Context, idToken string) (*auth.Token, error)
}

// FirebaseTokenValidator implements TokenValidator using Firebase Auth.
type FirebaseTokenValidator struct {
	client FirebaseAuthClient
	logger *logger.Log
}

// NewFirebaseTokenValidator creates a new FirebaseTokenValidator.
func NewFirebaseTokenValidator(client FirebaseAuthClient, logger *logger.Log) *FirebaseTokenValidator {
	return &FirebaseTokenValidator{
		client: client,
		logger: logger,
	}
}

// NewFireBaseAuthClient creates a new FirebaseAuthClient.
func NewFireBaseAuthClient(ctx context.Context) (FirebaseAuthClient, error) {
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase app: %w", err)
	}
	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting firebase auth client: %w", err)
	}
	return client, nil
}

// Verify validates the given ID token and checks for revocation.
func (validator *FirebaseTokenValidator) Verify(ctx context.Context, token, audience string) (*idtoken.Payload, error) {

	authToken, err := validator.client.VerifyIDTokenAndCheckRevoked(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	payload := &idtoken.Payload{
		Issuer:   authToken.Issuer,
		Audience: authToken.Audience,
		Expires:  authToken.Expires,
		IssuedAt: authToken.IssuedAt,
		Subject:  authToken.Subject,
		Claims:   authToken.Claims,
	}

	if authToken.Audience != audience {
		return nil, fmt.Errorf("audience mismatch: expected %q, got %q", audience, authToken.Audience)
	}

	return payload, nil
}
