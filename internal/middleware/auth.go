package middleware

import (
	"context"
	"net/http"
	"polytoken/internal/principal"
	"polytoken/internal/resolver"

	"github.com/golang-jwt/jwt/v5/request"
)

type contextKey string

const principalKey contextKey = "principal"

func Authenticate(r *resolver.Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			token, err := request.AuthorizationHeaderExtractor.ExtractToken(req)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p, err := r.Validate(req.Context(), token)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(req.Context(), principalKey, p)

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func PrincipalFrom(ctx context.Context) (*principal.Principal, bool) {
	p, ok := ctx.Value(principalKey).(*principal.Principal)
	return p, ok
}
