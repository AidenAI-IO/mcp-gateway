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

	// Support both "Bearer <token>" and raw token formats
	// This provides flexibility for different authentication scenarios
	parts := strings.SplitN(token, " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		token = parts[1]
	}
	// If not in "Bearer <token>" format, use the raw token as-is

	// Validate that we have a non-empty token
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("invalid token format: token is empty")
	}

	// Store token in context for later use
	ctx = context.WithValue(ctx, a.ArgKey, token)
	*r = *r.WithContext(ctx)

	return nil
}
