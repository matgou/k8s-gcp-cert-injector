package store

import "context"

// CertificateStore defines operations to synchronize TLS certificates with remote stores.
// Decoupling this from the GCP SDK allows extending this operator to support other backends
// like HashiCorp Vault, AWS ACM, or Azure Key Vault easily.
type CertificateStore interface {
	// Sync ensures the certificate and private key are active in the target store.
	// It returns a boolean indicating whether a change was made (create or update),
	// and an error if one occurred.
	// targetHash is the SHA-256 fingerprint computed by the controller.
	Sync(ctx context.Context, name string, certPEM, keyPEM []byte, targetHash string) (bool, error)

	// Delete ensures the certificate is removed from the target store.
	Delete(ctx context.Context, name string) error
}
type contextKey string

const (
	projectIDKey      contextKey = "gcp-project-id"
	universeDomainKey contextKey = "gcp-universe-domain"
)

// WithProjectID returns a new context with the target GCP Project ID.
func WithProjectID(ctx context.Context, projectID string) context.Context {
	if projectID == "" {
		return ctx
	}
	return context.WithValue(ctx, projectIDKey, projectID)
}

// GetProjectID retrieves the target GCP Project ID from the context, or falls back to the defaultID.
func GetProjectID(ctx context.Context, defaultID string) string {
	if val, ok := ctx.Value(projectIDKey).(string); ok && val != "" {
		return val
	}
	return defaultID
}

// WithUniverseDomain returns a new context with the target Universe Domain / suffix.
func WithUniverseDomain(ctx context.Context, universeDomain string) context.Context {
	if universeDomain == "" {
		return ctx
	}
	return context.WithValue(ctx, universeDomainKey, universeDomain)
}

// GetUniverseDomain retrieves the target Universe Domain / suffix from the context.
func GetUniverseDomain(ctx context.Context) string {
	if val, ok := ctx.Value(universeDomainKey).(string); ok {
		return val
	}
	return ""
}
