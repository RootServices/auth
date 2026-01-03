package validate

import (
	"context"
	"fmt"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/rootservices/auth/internal/logger"
	"github.com/stretchr/testify/assert"
)

type mockFactoryAuthClient struct{}

func (m *mockFactoryAuthClient) VerifyIDTokenAndCheckRevoked(ctx context.Context, idToken string) (*auth.Token, error) {
	return &auth.Token{}, nil
}

func TestTokenValidatorFactory(t *testing.T) {
	// Restore original function after test
	originalFunc := newFireBaseAuthClientFunc
	defer func() { newFireBaseAuthClientFunc = originalFunc }()

	tests := []struct {
		name           string
		validatorType  ValidatorType
		mockClientFunc func(ctx context.Context) (FirebaseAuthClient, error)
		wantType       string
		expectError    bool
	}{
		{
			name:          "google validator",
			validatorType: GoogleValidatorType,
			wantType:      "*validate.GoogleTokenValidator",
			expectError:   false,
		},
		{
			name:          "firebase validator success",
			validatorType: FirebaseValidatorType,
			mockClientFunc: func(ctx context.Context) (FirebaseAuthClient, error) {
				return &mockFactoryAuthClient{}, nil
			},
			wantType:    "*validate.FirebaseTokenValidator",
			expectError: false,
		},
		{
			name:          "firebase validator error",
			validatorType: FirebaseValidatorType,
			mockClientFunc: func(ctx context.Context) (FirebaseAuthClient, error) {
				return nil, fmt.Errorf("init error")
			},
			expectError: true,
		},
		{
			name:          "unknown validator",
			validatorType: ValidatorType("unknown"),
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockClientFunc != nil {
				newFireBaseAuthClientFunc = tt.mockClientFunc
			}

			logger := logger.New("INFO", "")
			got, err := TokenValidatorFactory(context.Background(), tt.validatorType, logger)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			gotType := fmt.Sprintf("%T", got)
			assert.Equal(t, tt.wantType, gotType)
		})
	}
}
