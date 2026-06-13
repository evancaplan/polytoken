package validator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"polytoken/internal/jwks"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// helper: create a key pair
func keyPair(t *testing.T) rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return *key
}

// helper: return jwks as json
func jwksDocAsJson(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	var jwk jwks.JwksDoc

	jwkKey := jwks.JwkKey{
		Kty: "RSA",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}

	jwk.Keys = append(jwk.Keys, jwkKey)

	jsonDoc, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	return jsonDoc
}

func mintRS256(t *testing.T, key *rsa.PrivateKey,
	kid string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func newJWKSServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksDocAsJson(t, key, kid))
	}))
}

func TestRs256Validate(t *testing.T) {
	key := keyPair(t)
	kid := "test-key-1"
	issuer := "https://issuer.example.com"

	server := newJWKSServer(t, &key, kid)
	defer server.Close()

	cache := jwks.NewCache(server.URL, nil)
	v := NewRs256Validator(issuer, cache)

	now := time.Now()

	t.Run("valid token", func(t *testing.T) {
		tok := mintRS256(t, &key, kid, jwt.MapClaims{
			"iss":   issuer,
			"sub":   "user-123",
			"exp":   now.Add(time.Hour).Unix(),
			"scope": "read write",
			"roles": []any{"admin"},
		})

		p, err := v.Validate(context.Background(), tok)
		if err != nil {
			t.Fatalf("expected valid token, got error: %v", err)
		}
		if p.Sub != "user-123" {
			t.Errorf("sub: got %q, want %q", p.Sub, "user-123")
		}
		if len(p.Scopes) != 2 {
			t.Errorf("scopes: got %v", p.Scopes)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		tok := mintRS256(t, &key, kid, jwt.MapClaims{
			"iss": "https://evil.example.com",
			"sub": "u",
			"exp": now.Add(time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for wrong issuer")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		tok := mintRS256(t, &key, kid, jwt.MapClaims{
			"iss": issuer,
			"sub": "u",
			"exp": now.Add(-time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		tok := mintRS256(t, &key, "some-other-kid", jwt.MapClaims{
			"iss": issuer,
			"sub": "u",
			"exp": now.Add(time.Hour).Unix(),
		})
		if _, err := v.Validate(context.Background(), tok); err == nil {
			t.Fatal("expected error for unknown kid")
		}
	})
}
