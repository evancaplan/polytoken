package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Issuers []IssuerConfig `yaml:"issuers"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("config: at least one issuer is required")
	}
	for i, iss := range cfg.Issuers {
		if err := iss.Validate(); err != nil {
			return nil, fmt.Errorf("config issuer #%d: %w", i, err)
		}
	}
	return &cfg, nil
}

type IssuerType string

const (
	TypeHS256 IssuerType = "hs256"
	TypeRS256 IssuerType = "rs256"
)

func (t IssuerType) Valid() bool {
	switch t {
	case TypeHS256, TypeRS256:
		return true
	default:
		return false
	}
}

type IssuerConfig struct {
	Issuer string         `yaml:"issuer"`
	Name   string         `yaml:"name"`
	Type   IssuerType     `yaml:"type"`
	HS256  *HS256Settings `yaml:"hs256"`
	RS256  *RS256Settings `yaml:"rs256"`
}

func (c IssuerConfig) Validate() error {
	if c.Name == "" {
		return errors.New("issuer: name is required")
	}
	if c.Issuer == "" {
		return fmt.Errorf("issuer %q: issuer (iss) is required", c.Name)
	}

	if !c.Type.Valid() {
		return fmt.Errorf("issuer: issuer %q is not a valid issuer", c.Name)
	}

	switch c.Type {
	case TypeHS256:
		if c.HS256 == nil {
			return fmt.Errorf("issuer %q: type hs256 requires hs256 settings", c.Name)
		}
		if c.HS256.Secret == "" {
			return fmt.Errorf("issuer %q: hs256 secret is required", c.Name)
		}
		if c.RS256 != nil {
			return fmt.Errorf("issuer %q: hs256 issuer must not have rs256 settings", c.Name)
		}
	case TypeRS256:
		if c.RS256 == nil {
			return fmt.Errorf("issuer %q: type rs256 requires rs256 settings", c.Name)
		}
		if c.RS256.JWKSURL == "" {
			return fmt.Errorf("issuer %q: rs256 jwksURL is required", c.Name)
		}
		if c.HS256 != nil {
			return fmt.Errorf("issuer %q: rs256 issuer must not have hs256 settings", c.Name)
		}
	default:
		return fmt.Errorf("issuer %q: unknown type %q", c.Name, c.Type)
	}
	return nil
}

type HS256Settings struct {
	Secret string
}

type RS256Settings struct {
	JWKSURL    string
	RefreshTTL time.Duration
}
