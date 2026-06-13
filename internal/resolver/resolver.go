package resolver

import (
	"context"
	"errors"
	"polytoken/internal/principal"
	"polytoken/internal/validator"
)

type Resolver struct {
	validators []validator.TokenValidator
}

var ErrNoValidator = errors.New("resolver: no validator can handle this token")

func NewResolver(validators []validator.TokenValidator) *Resolver {
	return &Resolver{validators: validators}
}

func (r *Resolver) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	for _, v := range r.validators {
		if v.CanHandle(token) {
			return v.Validate(ctx, token)
		}
	}
	return nil, ErrNoValidator
}
