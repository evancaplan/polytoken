package principal

import (
	"context"
	"time"
)

type Principal struct {
	Sub       string
	Iss       string
	Scopes    []string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Claims    map[string]interface{}
}

// ctxKey is unexported, so no other package can construct the key and
// store or overwrite a principal in a context.
type ctxKey struct{}

// WithPrincipal returns a copy of ctx carrying p. Only polytoken's middleware should call this.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the validated principal, and false if none is present
// or the stored pointer is nil.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}
