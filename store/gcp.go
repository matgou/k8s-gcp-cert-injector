package store

import (
	"context"
	"fmt"

	certificatemanager "cloud.google.com/go/certificatemanager/apiv1"
	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	// LabelCertHash represents the GCP label key we use to store the SHA-256 fingerprint.
	// Characters must be lowercase letters, numbers, hyphens, or underscores. Max 63 chars.
	LabelCertHash = "cert-sha256"
)

// GCPCertificateStore implements the CertificateStore interface for GCP Certificate Manager.
type GCPCertificateStore struct {
	client    *certificatemanager.Client
	projectID string
	location  string
}

// NewGCPCertificateStore initializes a new GCPCertificateStore.
func NewGCPCertificateStore(ctx context.Context, projectID, location string, opts ...option.ClientOption) (*GCPCertificateStore, error) {
	if projectID == "" {
		return nil, fmt.Errorf("gcp project ID cannot be empty")
	}
	if location == "" {
		location = "global" // Default to global locations
	}

	client, err := certificatemanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP Certificate Manager client: %w", err)
	}

	return &GCPCertificateStore{
		client:    client,
		projectID: projectID,
		location:  location,
	}, nil
}

// Sync uploads a self-managed TLS certificate to GCP Certificate Manager,
// performing a check on the existing label hash for complete idempotency.
func (s *GCPCertificateStore) Sync(ctx context.Context, name string, certPEM, keyPEM []byte, targetHash string) (bool, error) {
	projectID := GetProjectID(ctx, s.projectID)
	// Full resource path for GCP Certificate Manager
	certPath := fmt.Sprintf("projects/%s/locations/%s/certificates/%s", projectID, s.location, name)

	// Get the existing certificate, if any
	existingCert, err := s.client.GetCertificate(ctx, &certificatemanagerpb.GetCertificateRequest{
		Name: certPath,
	})

	if err != nil {
		// If resource does not exist, we create it
		if status.Code(err) == codes.NotFound {
			req := &certificatemanagerpb.CreateCertificateRequest{
				Parent:        fmt.Sprintf("projects/%s/locations/%s", projectID, s.location),
				CertificateId: name,
				Certificate: &certificatemanagerpb.Certificate{
					Labels: map[string]string{
						LabelCertHash: targetHash,
					},
					Type: &certificatemanagerpb.Certificate_SelfManaged{
						SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
							PemCertificate: string(certPEM),
							PemPrivateKey:  string(keyPEM),
						},
					},
				},
			}

			op, err := s.client.CreateCertificate(ctx, req)
			if err != nil {
				return false, fmt.Errorf("failed to call CreateCertificate API: %w", err)
			}

			// Wait for the Long Running Operation to finish
			if _, err := op.Wait(ctx); err != nil {
				return false, fmt.Errorf("failed waiting for CreateCertificate operation: %w", err)
			}

			return true, nil
		}

		// Any other API error is bubbled up
		return false, fmt.Errorf("failed to fetch existing certificate from GCP: %w", err)
	}

	// If the certificate exists, check if the SHA-256 hash matches
	existingHash := existingCert.Labels[LabelCertHash]
	if existingHash == targetHash {
		// Fingerprint is identical, no update is necessary!
		return false, nil
	}

	// Fingerprint has changed, perform an in-place update of the certificate and its hash label
	req := &certificatemanagerpb.UpdateCertificateRequest{
		Certificate: &certificatemanagerpb.Certificate{
			Name: certPath,
			Labels: map[string]string{
				LabelCertHash: targetHash,
			},
			Type: &certificatemanagerpb.Certificate_SelfManaged{
				SelfManaged: &certificatemanagerpb.Certificate_SelfManagedCertificate{
					PemCertificate: string(certPEM),
					PemPrivateKey:  string(keyPEM),
				},
			},
		},
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"self_managed", "labels"},
		},
	}

	op, err := s.client.UpdateCertificate(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to call UpdateCertificate API: %w", err)
	}

	// Wait for the Long Running Operation to finish
	if _, err := op.Wait(ctx); err != nil {
		return false, fmt.Errorf("failed waiting for UpdateCertificate operation: %w", err)
	}

	return true, nil
}

// Delete ensures a certificate is removed from GCP Certificate Manager.
func (s *GCPCertificateStore) Delete(ctx context.Context, name string) error {
	projectID := GetProjectID(ctx, s.projectID)
	certPath := fmt.Sprintf("projects/%s/locations/%s/certificates/%s", projectID, s.location, name)

	op, err := s.client.DeleteCertificate(ctx, &certificatemanagerpb.DeleteCertificateRequest{
		Name: certPath,
	})

	if err != nil {
		// If the resource is already gone, deletion is functionally complete and idempotent
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return fmt.Errorf("failed to call DeleteCertificate API: %w", err)
	}

	// Wait for deletion operation to conclude
	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("failed waiting for DeleteCertificate operation: %w", err)
	}

	return nil
}
