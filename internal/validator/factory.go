package validator

import (
	"fmt"
	"polytoken/internal/config"
	"polytoken/internal/jwks"
)

type validatorFactory func(cfg config.IssuerConfig) (TokenValidator, error)

var registry = map[config.IssuerType]validatorFactory{
	config.TypeHS256: buildHS256,
	config.TypeRS256: buildRS256,
}

func buildHS256(cfg config.IssuerConfig) (TokenValidator, error) {
	return NewHs256Validator(cfg.Issuer, []byte(cfg.HS256.Secret)), nil
}

func buildRS256(cfg config.IssuerConfig) (TokenValidator, error) {
	return NewRs256Validator(cfg.Issuer, jwks.NewCache(cfg.RS256.JwksUrl, nil)), nil
}

func BuildValidators(configs []config.IssuerConfig) ([]TokenValidator, error) {
	validators := make([]TokenValidator, 0, len(configs))
	for _, cfg := range configs {
		factory, ok := registry[cfg.Type]
		if !ok {
			return nil, fmt.Errorf("validator: unknown issuer type %q", cfg.Type)
		}

		validator, err := factory(cfg)
		if err != nil {
			return nil, fmt.Errorf("validator %q: %w", cfg.Name, err)
		}

		validators = append(validators, validator)
	}
	return validators, nil
}
