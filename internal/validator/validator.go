package validator

import "context"
import "github.com/evancaplan/polytoken/internal/principal"

type TokenValidator interface {
	Validate(ctx context.Context, token string) (*principal.Principal, error)
	CanHandle(token string) bool
}
