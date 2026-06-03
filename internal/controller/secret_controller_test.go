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
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/matgou/k8s-gcp-cert-injector/store"
)

var _ = Describe("Secret Controller", func() {
	const (
		SecretName      = "test-secret"
		SecretNamespace = "default"
		Timeout         = time.Second * 10
		Interval        = time.Millisecond * 250
		DefaultCertName = "k8s-cert-default-test-secret"
	)

	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
		mockStore.Reset()
	})

	AfterEach(func() {
		// Clean up created Secrets
		secret := &corev1.Secret{}
		err := k8sClient.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: SecretNamespace}, secret)
		if err == nil {
			// Remove finalizer to allow deletion
			secret.Finalizers = nil
			_ = k8sClient.Update(ctx, secret)
			_ = k8sClient.Delete(ctx, secret)
		}
	})

	Context("When reconciling a TLS Secret", func() {
		It("should ignore Secrets without the sync annotation", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Wait a bit and check that MockCertificateStore was NOT called
			Consistently(func() int {
				return len(mockStore.syncCalls)
			}, time.Second*2, Interval).Should(Equal(0))
		})

		It("should ignore non-TLS Secrets even if annotated", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync": "true",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			Consistently(func() int {
				return len(mockStore.syncCalls)
			}, time.Second*2, Interval).Should(Equal(0))
		})

		It("should successfully sync annotated TLS Secret and add finalizer", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync": "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// The controller should add the finalizer
			Eventually(func() bool {
				fetched := &corev1.Secret{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: SecretNamespace}, fetched)
				if err != nil {
					return false
				}
				return slices.Contains(fetched.Finalizers, "cert-injector.io/finalizer")
			}, Timeout, Interval).Should(BeTrue())

			// It should sync to the Mock store with the default name
			expectedName := DefaultCertName
			Eventually(func() bool {
				_, exists := mockStore.syncCalls[expectedName]
				return exists
			}, Timeout, Interval).Should(BeTrue())
		})

		It("should respect the name override annotation", func() {
			customName := "custom-gcp-cert-name"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync":      "true",
						"cert-injector.io/cert-name": customName,
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// It should sync to the Mock store with the custom name
			Eventually(func() bool {
				_, exists := mockStore.syncCalls[customName]
				return exists
			}, Timeout, Interval).Should(BeTrue())
		})

		It("should fail and not sync if the certificate name exceeds 63 characters", func() {
			veryLongName := "this-is-a-very-long-name-that-completely-exceeds-gcp-limits-of-sixty-three-characters"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync":      "true",
						"cert-injector.io/cert-name": veryLongName,
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// It should consistently NOT call sync since name validation fails
			Consistently(func() int {
				return len(mockStore.syncCalls)
			}, time.Second*2, Interval).Should(Equal(0))
		})

		It("should fail and not sync if the certificate name contains invalid characters", func() {
			invalidName := "Invalid_Name!"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync":      "true",
						"cert-injector.io/cert-name": invalidName,
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			Consistently(func() int {
				return len(mockStore.syncCalls)
			}, time.Second*2, Interval).Should(Equal(0))
		})

		It("should delete the remote certificate when Secret is deleted (using Finalizer)", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync": "true",
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			expectedName := DefaultCertName
			// Wait until finalizer and sync completed
			Eventually(func() bool {
				_, exists := mockStore.syncCalls[expectedName]
				return exists
			}, Timeout, Interval).Should(BeTrue())

			// Delete the Secret
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

			// It should have called Delete on the mock store
			Eventually(func() []string {
				return mockStore.deleteCalls
			}, Timeout, Interval).Should(ContainElement(expectedName))

			// The secret should be completely gone
			Eventually(func() error {
				fetched := &corev1.Secret{}
				return k8sClient.Get(ctx, client.ObjectKey{Name: SecretName, Namespace: SecretNamespace}, fetched)
			}, Timeout, Interval).Should(HaveOccurred())
		})

		It("should support syncing to a remote project via annotations", func() {
			remoteProject := "remote-gcp-project-123"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync":        "true",
						"cert-injector.io/gcp-project": remoteProject,
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			expectedName := DefaultCertName
			Eventually(func() bool {
				_, exists := mockStore.syncCalls[expectedName]
				return exists
			}, Timeout, Interval).Should(BeTrue())

			// Verify that the context passed to Sync contains the remote project ID
			Expect(mockStore.lastSyncContext).NotTo(BeNil())
			project := store.GetProjectID(mockStore.lastSyncContext, "")
			Expect(project).To(Equal(remoteProject))
		})

		It("should support syncing to a remote universe domain via annotations", func() {
			universeDomain := "emea-prod"
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      SecretName,
					Namespace: SecretNamespace,
					Annotations: map[string]string{
						"cert-injector.io/sync":            "true",
						"cert-injector.io/universe-domain": universeDomain,
					},
				},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("dummy-cert"),
					corev1.TLSPrivateKeyKey: []byte("dummy-key"),
				},
			}

			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// The name should NOT be suffixed with the universe domain
			expectedName := DefaultCertName
			Eventually(func() bool {
				_, exists := mockStore.syncCalls[expectedName]
				return exists
			}, Timeout, Interval).Should(BeTrue())

			// Verify that the context passed to Sync contains the universe domain
			Expect(mockStore.lastSyncContext).NotTo(BeNil())
			universe := store.GetUniverseDomain(mockStore.lastSyncContext)
			Expect(universe).To(Equal(universeDomain))
		})
	})
})
