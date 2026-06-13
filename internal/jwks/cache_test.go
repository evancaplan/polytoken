package jwks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// helper: build a JWKS JSON document for one RSA key under a given kid.
func jwksJSON(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	doc := JwksDoc{
		Keys: []JwkKey{{
			Kty: "RSA",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

func TestCacheLive(t *testing.T) {
	c := NewCache("https://www.googleapis.com/oauth2/v3/certs", nil)

	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	c.mu.RLock()
	n := len(c.keys)
	var someKid string
	for k := range c.keys {
		someKid = k
		break
	}
	c.mu.RUnlock()

	if n == 0 {
		t.Fatal("expected at least one key after refresh")
	}
	t.Logf("loaded %d keys, sample kid=%s", n, someKid)

	// known kid should resolve
	if _, err := c.Key(context.Background(), someKid); err != nil {
		t.Fatalf("expected to find kid %q: %v", someKid, err)
	}

	// bogus kid should miss (and trigger a refresh-retry, then error)
	if _, err := c.Key(context.Background(), "definitely-not-a-real-kid"); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}
func TestCacheRotation(t *testing.T) {
	// two different keys, two different kids
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	const kidA = "key-a"
	const kidB = "key-b"

	// `current` is what the server serves right now. The test mutates it
	// to simulate the issuer rotating its keys. mu guards it because the
	// HTTP handler runs on a different goroutine than the test.
	var (
		mu      sync.Mutex
		current []byte
	)
	setServed := func(b []byte) {
		mu.Lock()
		current = b
		mu.Unlock()
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body := current
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer server.Close()

	cache := NewCache(server.URL, nil)
	ctx := context.Background()

	// --- Phase 1: server serves key A ---
	setServed(jwksJSON(t, keyA, kidA))

	got, err := cache.Key(ctx, kidA)
	if err != nil {
		t.Fatalf("phase 1: expected to resolve %q, got error: %v", kidA, err)
	}
	if got.N.Cmp(keyA.PublicKey.N) != 0 {
		t.Fatal("phase 1: resolved key does not match key A")
	}

	setServed(jwksJSON(t, keyB, kidB))

	// kidB was never in the cache, so Key() should miss, refresh, refetch
	// (now getting B from the server), and resolve it.
	got, err = cache.Key(ctx, kidB)
	if err != nil {
		t.Fatalf("phase 2: expected rotation to resolve %q, got error: %v", kidB, err)
	}
	if got.N.Cmp(keyB.PublicKey.N) != 0 {
		t.Fatal("phase 2: resolved key does not match key B")
	}
}
