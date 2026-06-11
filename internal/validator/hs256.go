package validator

import (
	"context"
	"errors"
	"fmt"
	"polytoken/internal/principal"
	"strings"
	"time"

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

	iss, err := claims.GetIssuer()
	if err != nil {
		return nil, errors.New("hs256: missing issuer")
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return nil, errors.New("hs256: missing or invalid expiration")
	}

	sub, _ := claims.GetSubject()

	var issuedAt time.Time
	if ia, _ := claims.GetIssuedAt(); ia != nil {
		issuedAt = ia.Time
	}

	var scopes []string
	if raw, ok := claims["scope"]; ok {
		if s, ok := raw.(string); ok {
			scopes = strings.Fields(s)
		}
	}

	var roles []string
	if raw, ok := claims["roles"]; ok {
		if arr, ok := raw.([]any); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}
	// build the leftovers map: everything except the claims we promoted
	promotedClaims := map[string]bool{
		"sub": true, "iss": true, "iat": true, "exp": true,
		"scope": true, "roles": true,
		"nbf": true, // also a standard registered claim you're implicitly handling
	}

	leftoverClaims := make(map[string]any)
	for k, val := range claims {
		if !promotedClaims[k] {
			leftoverClaims[k] = val
		}
	}

	return &principal.Principal{
		Sub:       sub,
		Iss:       iss,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt.Time,
		Scopes:    scopes,
		Roles:     roles,
		Claims:    leftoverClaims,
	}, nil
}
