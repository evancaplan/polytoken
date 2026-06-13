package validator

import (
	"context"
	"errors"
	"fmt"
	"polytoken/internal/jwks"
	"polytoken/internal/principal"

	"github.com/golang-jwt/jwt/v5"
)

type Rs256Validator struct {
	issuer string
	cache  *jwks.Cache
}

func NewRs256Validator(issuer string, cache *jwks.Cache) *Rs256Validator {
	return &Rs256Validator{
		issuer: issuer,
		cache:  cache,
	}
}

func (v *Rs256Validator) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("rs256: unable to convert kid to string")
		}
		key, err := v.cache.Key(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("rs256: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("rs256: unexpected claims type")
	}

	return principalFromClaims(claims)
}

func (v *Rs256Validator) CanHandle(token string) bool {
	return issuerMatches(token, v.issuer)
}
