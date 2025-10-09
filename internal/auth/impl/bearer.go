package impl

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// BearerAuthenticator implements bearer token authentication
type BearerAuthenticator struct {
	Header string
	ArgKey string
}

// Authenticate implements types.Authenticator.Authenticate
func (a *BearerAuthenticator) Authenticate(ctx context.Context, r *http.Request) error {
	// Get token from header
	token := r.Header.Get(a.Header)
	if token == "" {
		return fmt.Errorf("missing %s header", a.Header)
	}

	// Validate token format (Bearer <token>)
	parts := strings.SplitN(token, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		token = parts[1]
	}
	//if len(parts) != 2 || parts[0] != "Bearer" {
	//	return fmt.Errorf("invalid token format")
	//}

	// Store token in context for later use
	//ctx = context.WithValue(ctx, a.ArgKey, parts[1])
	ctx = context.WithValue(ctx, a.ArgKey, token)
	*r = *r.WithContext(ctx)

	return nil
}
