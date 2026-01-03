package validate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"firebase.google.com/go/v4/auth"
)

type mockFirebaseAuthClient struct {
	verifyFunc func(ctx context.Context, idToken string) (*auth.Token, error)
}

func (m *mockFirebaseAuthClient) VerifyIDTokenAndCheckRevoked(ctx context.Context, idToken string) (*auth.Token, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, idToken)
	}
	return nil, errors.New("not implemented")
}

func TestFirebaseTokenValidator_Verify(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		audience      string
		mockVerify    func(ctx context.Context, idToken string) (*auth.Token, error)
		expectedError bool
		expectedSub   string
	}{
		{
			name:     "valid token",
			token:    "valid-token",
			audience: "my-project",
			mockVerify: func(ctx context.Context, idToken string) (*auth.Token, error) {
				return &auth.Token{
					Subject:  "user-123",
					Audience: "my-project",
				}, nil
			},
			expectedError: false,
			expectedSub:   "user-123",
		},
		{
			name:     "invalid token",
			token:    "invalid-token",
			audience: "my-project",
			mockVerify: func(ctx context.Context, idToken string) (*auth.Token, error) {
				return nil, errors.New("invalid token")
			},
			expectedError: true,
			expectedSub:   "",
		},
		{
			name:     "revoked token",
			token:    "revoked-token",
			audience: "my-project",
			mockVerify: func(ctx context.Context, idToken string) (*auth.Token, error) {
				return nil, errors.New("ID token has been revoked")
			},
			expectedError: true,
			expectedSub:   "",
		},
		{
			name:     "audience mismatch",
			token:    "valid-token",
			audience: "other-project",
			mockVerify: func(ctx context.Context, idToken string) (*auth.Token, error) {
				return &auth.Token{
					Subject:  "user-123",
					Audience: "my-project",
				}, nil
			},
			expectedError: true,
			expectedSub:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockFirebaseAuthClient{
				verifyFunc: tt.mockVerify,
			}
			v := NewFirebaseTokenValidator(client)

			payload, err := v.Verify(context.Background(), tt.token, tt.audience)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSub, payload.Subject)
			}
		})
	}
}
