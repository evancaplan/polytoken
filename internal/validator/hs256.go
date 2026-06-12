package validator

import (
	"context"
	"errors"
	"fmt"
	"polytoken/internal/principal"

	"github.com/golang-jwt/jwt/v5"
)

type Hs256Validator struct {
	issuer string
	secret []byte
}

func NewHs256Validator(expectedIssuer string, secret []byte) *Hs256Validator {
	return &Hs256Validator{
		issuer: expectedIssuer,
		secret: secret,
	}
}

func (v *Hs256Validator) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		return v.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("hs256: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("hs256: unexpected claims type")
	}

	return principalFromClaims(claims)
}
