package principal

import (
	"context"
	"testing"
)

type otherKey struct{}

func TestFromContext(t *testing.T) {
	p := &Principal{Sub: "user-123", Iss: "https://issuer.example.com"}

	tests := []struct {
		name   string
		ctx    context.Context
		want   *Principal
		wantOK bool
	}{
		{
			name:   "empty context",
			ctx:    context.Background(),
			want:   nil,
			wantOK: false,
		},
		{
			name:   "stored principal",
			ctx:    WithPrincipal(context.Background(), p),
			want:   p,
			wantOK: true,
		},
		{
			name:   "stored nil principal",
			ctx:    WithPrincipal(context.Background(), nil),
			want:   nil,
			wantOK: false,
		},
		{
			name:   "principal under a different key",
			ctx:    context.WithValue(context.Background(), otherKey{}, p),
			want:   nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromContext(tt.ctx)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("FromContext() = (%p, %v), want (%p, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
