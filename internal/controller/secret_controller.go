/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/matgou/k8s-gcp-cert-injector/store"
)

const (
	// AnnotationSync is the annotation required on a Secret to trigger synchronization.
	AnnotationSync = "cert-injector.io/sync"

	// AnnotationCertName is an optional annotation to override the replicated certificate resource name.
	AnnotationCertName = "cert-injector.io/cert-name"

	// AnnotationGCPProject is an optional annotation to override the destination GCP Project ID.
	AnnotationGCPProject = "cert-injector.io/gcp-project"

	// AnnotationUniverseDomain is an optional annotation to manage/scope by a remote universe domain.
	AnnotationUniverseDomain = "cert-injector.io/universe-domain"

	// FinalizerName is the standard finalizer name attached to the K8s Secret.
	FinalizerName = "cert-injector.io/finalizer"
)

// Regex matching the naming standards of GCP Certificate Manager (lowercase letters, numbers, hyphens, starts with letter).
var gcpResourceNameRegex = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	CertStore store.CertificateStore
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=secrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which watches
// TLS Secrets with the matching synchronization annotations, and replicates their
// certificates into the configured CertificateStore backend (e.g. GCP Certificate Manager).
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("secret", req.NamespacedName)

	// 1. Fetch the Secret instance
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			// Secret was deleted, handled gracefully by Finalizer below or it was already deleted.
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to retrieve Secret resource")
		return ctrl.Result{}, err
	}

	// 1.5 Extract target GCP Project and Universe Domain from annotations
	gcpProject := secret.Annotations[AnnotationGCPProject]
	universeDomain := secret.Annotations[AnnotationUniverseDomain]

	ctx = store.WithProjectID(ctx, gcpProject)
	ctx = store.WithUniverseDomain(ctx, universeDomain)

	// 2. Determine Certificate Name
	certName := secret.Annotations[AnnotationCertName]
	if certName == "" {
		// Strict, predictable default naming scheme (highly integrated with Terraform)
		certName = fmt.Sprintf("k8s-cert-%s-%s", secret.Namespace, secret.Name)
	}
	if universeDomain != "" {
		certName = fmt.Sprintf("%s-%s", certName, universeDomain)
	}

	// 3. Handle Deletion (Finalizer check)
	if !secret.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&secret, FinalizerName) {
			log.Info("Secret marked for deletion; removing remote certificate", "certificateName", certName)

			// Pre-validate the certificate name before deleting to avoid raw client library crashes.
			// If it's invalid, it was never created, so we can clean up the finalizer immediately.
			if err := validateGCPResourceName(certName); err != nil {
				log.Error(err, "Invalid certificate name during deletion; skipping store deletion and cleaning up finalizer", "certificateName", certName)
			} else {
				if err := r.CertStore.Delete(ctx, certName); err != nil {
					log.Error(err, "Failed to delete remote certificate from store", "certificateName", certName)
					return ctrl.Result{}, err
				}
				log.Info("Successfully deleted remote certificate from store", "certificateName", certName)
			}

			// Remove finalizer so Kubernetes can delete the resource
			controllerutil.RemoveFinalizer(&secret, FinalizerName)
			if err := r.Update(ctx, &secret); err != nil {
				log.Error(err, "Failed to remove finalizer from Secret")
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// 4. Inject Finalizer for safe deletion tracking
	if !controllerutil.ContainsFinalizer(&secret, FinalizerName) {
		controllerutil.AddFinalizer(&secret, FinalizerName)
		if err := r.Update(ctx, &secret); err != nil {
			log.Error(err, "Failed to append finalizer to Secret")
			return ctrl.Result{}, err
		}
		log.Info("Successfully attached synchronization finalizer to Secret")
		return ctrl.Result{}, nil
	}

	// 5. Validation of Secret Data (Must contain standard K8s TLS keys)
	certPEM, hasCert := secret.Data[corev1.TLSCertKey]
	rawKeyPEM, hasKey := secret.Data[corev1.TLSPrivateKeyKey]
	if !hasCert || !hasKey || len(certPEM) == 0 || len(rawKeyPEM) == 0 {
		log.Error(nil, "Secret type is kubernetes.io/tls but lacks 'tls.crt' or 'tls.key' data. Skipping sync.")
		return ctrl.Result{}, nil // No requeue since user input must be modified to proceed
	}

	// For maximum security and compliance with Defense in Depth (buffer zeroing),
	// we make a local copy of rawKeyPEM, and zero out the private key copy immediately
	// when we exit Reconcile. This avoids modifying the client-go cache directly.
	keyPEM := make([]byte, len(rawKeyPEM))
	copy(keyPEM, rawKeyPEM)
	defer func() {
		for i := range keyPEM {
			keyPEM[i] = 0
		}
	}()

	// 6. Pre-validate Certificate Name compliance with remote store naming constraints
	if err := validateGCPResourceName(certName); err != nil {
		log.Error(err, "Resolved certificate name is invalid. Sync halted.", "resolvedName", certName)
		return ctrl.Result{}, nil // No requeue, the user must update the naming annotation or resource name
	}

	// 7. Compute high-fidelity SHA-256 fingerprint for idempotency checking
	targetHash := calculateSHA256(certPEM, keyPEM)

	// 8. Execute store synchronization
	changed, err := r.CertStore.Sync(ctx, certName, certPEM, keyPEM, targetHash)
	if err != nil {
		log.Error(err, "Failed to synchronize certificate to the backend store", "certificateName", certName)
		return ctrl.Result{}, err // Requeue with exponential backoff on store failures
	}

	if changed {
		log.Info("Successfully synchronized certificate to the remote store", "certificateName", certName, "hash", targetHash)
	} else {
		log.V(1).Info("Remote certificate matches current local state. Sync skipped (idempotent).", "certificateName", certName)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager, adding strict predicates
// so that only annotated corev1.Secrets of type kubernetes.io/tls trigger the reconcile loop.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return r.shouldReconcile(e.Object)
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return r.shouldReconcile(e.ObjectNew) || r.shouldReconcile(e.ObjectOld)
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return r.shouldReconcile(e.Object)
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return r.shouldReconcile(e.Object)
			},
		}).
		Named("secret").
		Complete(r)
}

// shouldReconcile evaluates if a Secret resource meets synchronization requirements.
func (r *SecretReconciler) shouldReconcile(obj client.Object) bool {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return false
	}
	// Filters on the sync annotation
	if secret.Annotations == nil || secret.Annotations[AnnotationSync] != "true" {
		return false
	}
	// Strictly processes kubernetes.io/tls secrets
	return secret.Type == corev1.SecretTypeTLS
}

// validateGCPResourceName validates if a certificate name complies with GCP naming restrictions (Max 63 characters).
func validateGCPResourceName(name string) error {
	if len(name) > 63 {
		return fmt.Errorf("certificate name length %d exceeds GCP limit of 63 characters", len(name))
	}
	if !gcpResourceNameRegex.MatchString(name) {
		return fmt.Errorf("name must start with a lowercase letter, contain only lowercase alphanumeric characters or hyphens, and end with a letter or number")
	}
	return nil
}

// calculateSHA256 computes a hexadecimal SHA-256 hash of concatenated PEM data for safe, stateless fingerprinting.
func calculateSHA256(cert, key []byte) string {
	h := sha256.New()
	h.Write(cert)
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil))
}
