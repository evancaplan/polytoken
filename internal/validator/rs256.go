package validator

import (
	"context"
	"errors"
	"polytoken/internal/principal"
)

type Rs256Validator struct {
}

func NewRs256Validator() *Rs256Validator {
	return &Rs256Validator{}
}

func (v *Rs256Validator) Validate(ctx context.Context, token string) (*principal.Principal, error) {
	return nil, errors.New("not implemented")
}
