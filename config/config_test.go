package config

import (
	"strings"
	"testing"
)

func TestIssuerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     IssuerConfig
		wantErr string // substring we expect; "" means expect success
	}{
		{
			name: "valid hs256",
			cfg: IssuerConfig{
				Name: "legacy", Issuer: "https://i.example.com", Type: TypeHS256,
				HS256: &HS256Settings{Secret: "s"},
			},
			wantErr: "",
		},
		{
			name: "valid rs256",
			cfg: IssuerConfig{
				Name: "okta", Issuer: "https://okta", Type: TypeRS256,
				RS256: &RS256Settings{JwksUrl: "https://okta/keys"},
			},
			wantErr: "",
		},
		{
			name:    "missing name",
			cfg:     IssuerConfig{Issuer: "x", Type: TypeHS256, HS256: &HS256Settings{Secret: "s"}},
			wantErr: "name is required",
		},
		{
			name:    "invalid type",
			cfg:     IssuerConfig{Name: "x", Issuer: "y", Type: "es256"},
			wantErr: "invalid type",
		},
		{
			name:    "hs256 missing secret",
			cfg:     IssuerConfig{Name: "x", Issuer: "y", Type: TypeHS256, HS256: &HS256Settings{}},
			wantErr: "secret is required",
		},
		{
			name: "hs256 with rs256 settings",
			cfg: IssuerConfig{
				Name: "x", Issuer: "y", Type: TypeHS256,
				HS256: &HS256Settings{Secret: "s"}, RS256: &RS256Settings{JwksUrl: "z"},
			},
			wantErr: "must not have rs256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Issuers) != 2 {
		t.Fatalf("expected 2 issuers, got %d", len(cfg.Issuers))
	}
	if cfg.Issuers[1].RS256.JwksUrl == "" {
		t.Fatal("jwksUrl did not unmarshal — check your yaml tags")
	}
}
