package validate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/idtoken"
)

func TestGoogleTokenValidator_Verify(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		audience      string
		mockValidate  func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error)
		expectedError bool
		expectedSub   string
	}{
		{
			name:     "valid token",
			token:    "valid-token",
			audience: "my-audience",
			mockValidate: func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Subject: "1234567890"}, nil
			},
			expectedError: false,
			expectedSub:   "1234567890",
		},
		{
			name:     "invalid token",
			token:    "invalid-token",
			audience: "my-audience",
			mockValidate: func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
				return nil, errors.New("idtoken: invalid token")
			},
			expectedError: true,
			expectedSub:   "",
		},
		{
			name:     "expired token",
			token:    "expired-token",
			audience: "my-audience",
			mockValidate: func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
				return nil, errors.New("idtoken: expired")
			},
			expectedError: true,
			expectedSub:   "",
		},
		{
			name:     "wrong audience",
			token:    "valid-token",
			audience: "wrong-audience",
			mockValidate: func(ctx context.Context, idToken string, audience string) (*idtoken.Payload, error) {
				return nil, errors.New("idtoken: audience mismatch")
			},
			expectedError: true,
			expectedSub:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &GoogleTokenValidator{
				validatorFunc: tt.mockValidate,
			}

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
