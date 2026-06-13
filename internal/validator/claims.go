package validator

import (
	"errors"
	"polytoken/internal/principal"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func issuerMatches(token, expectedIssuer string) bool {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		return false
	}
	iss, _ := claims.GetIssuer()
	return iss == expectedIssuer
}

func principalFromClaims(claims jwt.MapClaims) (*principal.Principal, error) {
	iss, err := claims.GetIssuer()
	if err != nil {
		return nil, errors.New("missing issuer")
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil {
		return nil, errors.New("missing or invalid expiration")
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
		"nbf": true,
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
