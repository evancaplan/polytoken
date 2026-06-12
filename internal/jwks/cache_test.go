package jwks

import (
	"context"
	"testing"
)

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
