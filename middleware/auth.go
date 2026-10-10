package middleware

import (
	"context"
	"github.com/evancaplan/polytoken/principal"
	"github.com/evancaplan/polytoken/resolver"
	"net/http"

	"github.com/golang-jwt/jwt/v5/request"
)

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
			ctx := principal.WithPrincipal(req.Context(), p)

			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// PrincipalFrom returns the principal stored by Authenticate.
//
// Deprecated: use principal.FromContext.
func PrincipalFrom(ctx context.Context) (*principal.Principal, bool) {
	return principal.FromContext(ctx)
}
