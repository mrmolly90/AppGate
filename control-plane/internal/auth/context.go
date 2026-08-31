package auth

import "context"

type contextKey string

const IdentityKey contextKey = "appgate_identity"

// Identity represents an authenticated application/user
type Identity struct {
    ProjectID string
    UserID    string
    Roles     []string
    Scopes    []string
}

func IdentityFromContext(ctx context.Context) Identity {
    if id, ok := ctx.Value(IdentityKey).(Identity); ok {
        return id
    }
    return Identity{ProjectID: "default", UserID: "anonymous", Roles: []string{"anonymous"}}
}

func WithIdentity(ctx context.Context, id Identity) context.Context {
    return context.WithValue(ctx, IdentityKey, id)
}
