package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type JwksDoc struct {
	Keys []JwkKey `json:"keys"`
}

type JwkKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
}

type Cache struct {
	url    string
	client *http.Client

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
}

func NewCache(url string, client *http.Client) *Cache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Cache{
		url:    url,
		client: client,
		keys:   make(map[string]*rsa.PublicKey),
	}
}

func (c *Cache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)

	if err != nil {
		return fmt.Errorf("jwks: could not create request to fetch jwks: %w", err)
	}

	resp, err := c.client.Do(req)

	if err != nil {
		return fmt.Errorf("jwks: failed to fetch jwks doc: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: non-200 response from jwks endpoint: %d", resp.StatusCode)
	}

	var doc JwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, key := range doc.Keys {
		pub, err := jwkToRSA(key)
		if err != nil {
			continue
		}
		keys[key.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

func (c *Cache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// first read; lock, grab, release immediately
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}

	// miss, refresh with NO lock held (Refresh takes the write lock itself)
	if err := c.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("jwks: refresh for kid %q: %w", kid, err)
	}

	// second read; lock, grab, release immediately
	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: key id %q not found", kid)
	}
	return key, nil
}

func jwkToRSA(k JwkKey) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)

	// exponent is a big-endian integer, usually 65537
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
