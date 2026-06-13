package resolver

import (
	"context"
	"testing"

	"polytoken/internal/principal"
	"polytoken/internal/validator"
)

type stubValidator struct {
	name           string
	canHandle      bool
	validateCalled bool
}

func (s *stubValidator) CanHandle(token string) bool {
	return s.canHandle
}

func (s *stubValidator) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	s.validateCalled = true
	return &principal.Principal{Sub: s.name}, nil
}

func TestResolver_RoutesToMatchingValidator(t *testing.T) {
	a := &stubValidator{name: "a", canHandle: false}
	b := &stubValidator{name: "b", canHandle: true}
	c := &stubValidator{name: "c", canHandle: false}

	r := NewResolver([]validator.TokenValidator{a, b, c})

	p, err := r.Validate(context.Background(), "any-token")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if p.Sub != "b" {
		t.Errorf("routed to wrong validator: got %q, want %q", p.Sub, "b")
	}
	if a.validateCalled || c.validateCalled {
		t.Error("a non-matching validator's Validate was called")
	}
	if !b.validateCalled {
		t.Error("matching validator's Validate was not called")
	}
}

func TestResolver_NoMatch(t *testing.T) {
	a := &stubValidator{name: "a", canHandle: false}
	b := &stubValidator{name: "b", canHandle: false}

	r := NewResolver([]validator.TokenValidator{a, b})

	_, err := r.Validate(context.Background(), "any-token")
	if err == nil {
		t.Fatal("expected error when no validator matches")
	}
}
