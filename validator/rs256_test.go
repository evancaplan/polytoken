package validator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"github.com/evancaplan/polytoken/jwks"
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

func FuzzRs256Validate(f *testing.F) {
	key := keyPair(&testing.T{})
	kid := "test-key-1"
	issuer := "https://issuer.example.com"

	server := newJWKSServer(&testing.T{}, &key, kid)
	defer server.Close()

	cache := jwks.NewCache(server.URL, nil)
	v := NewRs256Validator(issuer, cache)
	now := time.Now()

	// seed corpus
	f.Add(mintRS256(&testing.T{}, &key, kid, jwt.MapClaims{
		"iss": issuer, "sub": "user-123", "exp": now.Add(time.Hour).Unix(),
	}))
	f.Add(mintRS256(&testing.T{}, &key, "unknown-kid", jwt.MapClaims{
		"iss": issuer, "sub": "u", "exp": now.Add(time.Hour).Unix(),
	}))

	// classic alg-confusion probes: these are worth seeding explicitly,
	// not just hoping the mutator stumbles onto them
	f.Add(forgeAlgNone(issuer, "user-123", now.Add(time.Hour).Unix()))
	f.Add(forgeHS256SignedWithPublicKeyPEM(&key.PublicKey, issuer, "user-123", now.Add(time.Hour).Unix()))
	f.Add("")
	f.Add("....")
	f.Add("not-a-jwt")

	f.Fuzz(func(t *testing.T, token string) {
		p, err := v.Validate(context.Background(), token)

		if err == nil && p.Sub == "" {
			t.Errorf("validated token with empty sub: %q", token)
		}
	})
}

// forges a token with alg=none and no signature — some libraries
// historically trusted this if not explicitly rejected
func forgeAlgNone(iss, sub string, exp int64) string {
	header := `{"alg":"none","typ":"JWT"}`
	claims, _ := json.Marshal(jwt.MapClaims{"iss": iss, "sub": sub, "exp": exp})
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc([]byte(header)) + "." + enc(claims) + "."
}

// forges a token claiming HS256, signed using the RSA public key's PEM
// bytes as the HMAC secret — the classic RS256->HS256 confusion attack,
// since public keys are... public
func forgeHS256SignedWithPublicKeyPEM(pub *rsa.PublicKey, iss, sub string, exp int64) string {
	pubPEM := publicKeyToPEM(pub) // marshal to PEM bytes
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": iss, "sub": sub, "exp": exp,
	})
	signed, _ := tok.SignedString(pubPEM)
	return signed
}

func publicKeyToPEM(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// seed-generation helper, panic is fine here — this only
		// runs at fuzz setup time, never on fuzzer-controlled input
		panic(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block)
}
