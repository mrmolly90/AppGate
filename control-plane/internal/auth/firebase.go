// =============================================================================
// AppGate Control Plane — Firebase Auth Integration
// =============================================================================
// Verifies Firebase-issued ID tokens from dev-portal users.
// Uses the Firebase Admin SDK with credentials from environment variables.
// =============================================================================

package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

// FirebaseVerifier handles Firebase JWT token verification.
type FirebaseVerifier struct {
	client *auth.Client
}

// NewFirebaseVerifier creates a Firebase verifier from env vars.
// Reads FIREBASE_* variables from .env / environment.
func NewFirebaseVerifier() (*FirebaseVerifier, error) {
	projectID := os.Getenv("FIREBASE_PROJECT_ID")
	if projectID == "" {
		return nil, fmt.Errorf("FIREBASE_PROJECT_ID not set")
	}

	clientEmail := os.Getenv("FIREBASE_CLIENT_EMAIL")
	privateKeyID := os.Getenv("FIREBASE_PRIVATE_KEY_ID")
	privateKey := os.Getenv("FIREBASE_PRIVATE_KEY")
	clientID := os.Getenv("FIREBASE_CLIENT_ID")
	authURI := os.Getenv("FIREBASE_AUTH_URI")
	tokenURI := os.Getenv("FIREBASE_TOKEN_URI")
	authProviderCertURL := os.Getenv("FIREBASE_AUTH_PROVIDER_CERT_URL")
	clientCertURL := os.Getenv("FIREBASE_CLIENT_CERT_URL")

	if clientEmail == "" || privateKey == "" {
		return nil, fmt.Errorf("FIREBASE_CLIENT_EMAIL and FIREBASE_PRIVATE_KEY must be set")
	}

	// Build service account JSON from env vars
	saJSON := fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "%s",
		"private_key_id": "%s",
		"private_key": "%s",
		"client_email": "%s",
		"client_id": "%s",
		"auth_uri": "%s",
		"token_uri": "%s",
		"auth_provider_x509_cert_url": "%s",
		"client_x509_cert_url": "%s"
	}`, projectID, privateKeyID, strings.ReplaceAll(privateKey, "\n", "\\n"),
		clientEmail, clientID, authURI, tokenURI, authProviderCertURL, clientCertURL)

	opt := option.WithCredentialsJSON([]byte(saJSON))
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return nil, fmt.Errorf("firebase app init failed: %w", err)
	}

	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, fmt.Errorf("firebase auth client failed: %w", err)
	}

	return &FirebaseVerifier{client: client}, nil
}

// VerifyToken verifies a Firebase ID token and returns the UID.
func (fv *FirebaseVerifier) VerifyToken(idToken string) (string, error) {
	token, err := fv.client.VerifyIDToken(context.Background(), idToken)
	if err != nil {
		return "", fmt.Errorf("firebase token verification failed: %w", err)
	}
	return token.UID, nil
}

// Middleware returns HTTP middleware that verifies Firebase tokens.
func (fv *FirebaseVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
			return
		}

		uid, err := fv.VerifyToken(parts[1])
		if err != nil {
			log.Warn().Err(err).Msg("Firebase token validation failed")
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		// Set UID in context
		ctx := context.WithValue(r.Context(), contextKey("firebase_uid"), uid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
