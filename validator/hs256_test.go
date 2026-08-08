package validator

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// helper: sign an HS256 token with given claims and secret
func mintHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return s
}

func TestHs256Validate(t *testing.T) {
	secret := []byte("test-secret")
	issuer := "https://issuer.example.com"
	v := NewHs256Validator(issuer, secret)

	now := time.Now()

	t.Run("valid token", func(t *testing.T) {
		tok := mintHS256(t, secret, jwt.MapClaims{
			"iss":   issuer,
			"sub":   "user-123",
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"scope": "read write",
			"roles": []any{"admin", "editor"},
		})
		p, err := v.Validate(context.Background(), tok)
		if err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
		if p.Sub != "user-123" {
			t.Errorf("sub: got %q", p.Sub)
		}
		if len(p.Scopes) != 2 || p.Scopes[0] != "read" {
			t.Errorf("scopes: got %v", p.Scopes)
		}
		if len(p.Roles) != 2 || p.Roles[1] != "editor" {
			t.Errorf("roles: got %v", p.Roles)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		tok := mintHS256(t, secret, jwt.MapClaims{
			"iss": issuer, "sub": "u", "exp": now.Add(-time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		tok := mintHS256(t, []byte("WRONG"), jwt.MapClaims{
			"iss": issuer, "sub": "u", "exp": now.Add(time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for bad signature")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		tok := mintHS256(t, secret, jwt.MapClaims{
			"iss": "https://evil.example.com", "sub": "u", "exp": now.Add(time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for wrong issuer")
		}
	})

	t.Run("missing exp", func(t *testing.T) {
		tok := mintHS256(t, secret, jwt.MapClaims{"iss": issuer, "sub": "u"})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for missing exp")
		}
	})
}

func FuzzHs256Validate(f *testing.F) {
	secret := []byte("test-secret")
	issuer := "https://issuer.example.com"
	v := NewHs256Validator(issuer, secret)
	now := time.Now()

	// seed corpus: reuse your existing valid/invalid cases as starting points
	f.Add(mintHS256(&testing.T{}, secret, jwt.MapClaims{
		"iss": issuer, "sub": "user-123",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"scope": "read write", "roles": []any{"admin", "editor"},
	}))
	f.Add(mintHS256(&testing.T{}, secret, jwt.MapClaims{
		"iss": issuer, "sub": "u", "exp": now.Add(-time.Hour).Unix(),
	}))
	f.Add("not-a-jwt-at-all")
	f.Add("")
	f.Add("....")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.")

	f.Fuzz(func(t *testing.T, token string) {
		// the only real invariant: it must never panic,
		// regardless of what garbage comes in
		p, err := v.Validate(context.Background(), token)

		// if it claims success, the payload better be internally consistent
		if err == nil {
			if p.Sub == "" {
				t.Errorf("validated token with empty sub: %q", token)
			}
		}
	})
}
