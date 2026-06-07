package validator

import "context"

type TokenValidator interface {
	Validate(ctx context.Context, token string) (*Principal, error)
}
