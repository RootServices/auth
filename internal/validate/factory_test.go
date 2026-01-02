package validate

import (
	"context"
	"fmt"
	"testing"

	"firebase.google.com/go/v4/auth"
	"github.com/stretchr/testify/assert"
)

type mockFactoryAuthClient struct{}

func (m *mockFactoryAuthClient) VerifyIDTokenAndCheckRevoked(ctx context.Context, idToken string) (*auth.Token, error) {
	return &auth.Token{}, nil
}

func TestNewTokenValidator(t *testing.T) {
	tests := []struct {
		name           string
		validatorType  ValidatorType
		firebaseClient FirebaseAuthClient
		wantType       string // string representation of the expected type
		expectError    bool
	}{
		{
			name:          "google validator",
			validatorType: GoogleValidatorType,
			wantType:      "*validate.GoogleTokenValidator",
			expectError:   false,
		},
		{
			name:           "firebase validator with client",
			validatorType:  FirebaseValidatorType,
			firebaseClient: &mockFactoryAuthClient{},
			wantType:       "*validate.FirebaseTokenValidator",
			expectError:    false,
		},
		{
			name:           "firebase validator missing client",
			validatorType:  FirebaseValidatorType,
			firebaseClient: nil,
			expectError:    true,
		},
		{
			name:          "unknown validator",
			validatorType: ValidatorType("unknown"),
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTokenValidator(tt.validatorType, tt.firebaseClient)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, got)

			// We can check the type using fmt.Sprintf("%T", got)
			gotType := fmt.Sprintf("%T", got)
			assert.Equal(t, tt.wantType, gotType)
		})
	}
}
