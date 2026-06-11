package validator

import (
	"context"
	"errors"
	"polytoken/internal/principal"
)

type Hs256Validator struct {
}

func NewHs256Validator() *Hs256Validator {
	return &Hs256Validator{}
}

func (v *Hs256Validator) Validate(ctx context.Context, token string) (*principal.Principal, error) {

	return nil, errors.New("not implemented")
}
