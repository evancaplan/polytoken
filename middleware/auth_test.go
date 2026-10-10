package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"github.com/evancaplan/polytoken/validator"
	"github.com/golang-jwt/jwt/v5"
)

func mintHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return s
}

func TestAuthenticate(t *testing.T) {
	secret := []byte("test-secret")
	issuer := "https://issuer.example.com"
	r := resolver.NewResolver([]validator.TokenValidator{validator.NewHs256Validator(issuer, secret)})
	now := time.Now()

	tests := []struct {
		name       string
		authHeader string
		wantNext   bool
		wantStatus int
	}{
		{
			name: "valid token",
			authHeader: "Bearer " + mintHS256(t, secret, jwt.MapClaims{
				"iss": issuer, "sub": "user-123", "exp": now.Add(time.Hour).Unix(),
			}),
			wantNext:   true,
			wantStatus: http.StatusOK,
		},
		{
			name: "wrong secret",
			authHeader: "Bearer " + mintHS256(t, []byte("wrong-secret"), jwt.MapClaims{
				"iss": issuer, "sub": "user-123", "exp": now.Add(time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired token",
			authHeader: "Bearer " + mintHS256(t, secret, jwt.MapClaims{
				"iss": issuer, "sub": "user-123", "exp": now.Add(-time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing header",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reached bool
			next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				reached = true
				p, ok := principal.FromContext(req.Context())
				if !ok {
					t.Fatal("principal.FromContext returned false in next handler")
				}
				if p.Sub != "user-123" || p.Iss != issuer {
					t.Errorf("principal: got sub=%q iss=%q", p.Sub, p.Iss)
				}
			})

			req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			Authenticate(r)(next).ServeHTTP(rec, req)

			if reached != tt.wantNext {
				t.Errorf("next reached = %v, want %v", reached, tt.wantNext)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
