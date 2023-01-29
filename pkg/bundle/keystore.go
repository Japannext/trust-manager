/*
Copyright 2021 The cert-manager Authors.

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

package bundle

import (
	"context"
    "bytes"
	"errors"
    "time"
    "bufio"
	"encoding/pem"
    "crypto/x509"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
    "go.step.sm/crypto/x509util"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
    ks "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func (b *bundle) syncKeyStore(ctx context.Context, log logr.Logger,
    bundle *trustapi.Bundle,
    pemData []byte,
) (bool, error) {

    updated, kd, err := b.syncKeyStoreStatus(ctx, log, bundle, pemData)

    if updated {
        bundle.Status.KeyStore = kd
        err := b.targetDirectClient.Status().Update(ctx, bundle)
        if err != nil {
            return false, err
        }
    }

    return updated, err

}

// Sync the value of the
func (b *bundle) syncKeyStoreStatus(ctx context.Context, log logr.Logger,
    bundle *trustapi.Bundle,
    pemData []byte,
) (bool, []byte, error) {

    target := bundle.Spec.Target
    password := []byte(target.KeyStore.Password)
    keystore := ks.New()
    updated := false

    err := keystore.Load(bytes.NewReader(bundle.Status.KeyStore), password)
    if err != nil {
        b.recorder.Eventf(bundle, corev1.EventTypeWarning, "KeyStoreError", "Could not load existing keystore in bundle status: %s.The keystore will be replaced", err)
    }

    // Quick way to verify alias existence for removing them
    aliases := make(map[string]bool)

    for i, cert := range b.parsePem(ctx, log, bundle, pemData) {
        alias, err := getCertAlias(cert)
        if err != nil {
            b.recorder.Eventf(bundle, corev1.EventTypeWarning, "KeyStoreError", "Certificate in position #%d is not a valid x509 certificate, cannot generate alias from fingerprint: %s", i, err)
            continue
        }
        aliases[alias] = true
        oldEntry, err := keystore.GetTrustedCertificateEntry(alias)

        // Insert/Update the certificate
        if errors.Is(err, ks.ErrEntryNotFound) || bytes.Compare(oldEntry.Certificate.Content, cert.Content) != 0 {
            err := keystore.SetTrustedCertificateEntry(alias, ks.TrustedCertificateEntry{
                CreationTime: time.Now(),
                Certificate: cert,
            })
            if err != nil {
                b.recorder.Eventf(bundle, corev1.EventTypeWarning, "KeyStoreError", "Error appending TrustedCertificateEntry (alias: '%s'): %s", alias, err)
            }
            updated = true
        }
    }

    // Delete certificates that are not in the source PEM
    for _, a := range keystore.Aliases() {
        if _, ok := aliases[a]; !ok {
            keystore.DeleteEntry(a)
            updated = true
        }
    }

    var keystoreData bytes.Buffer
    if err := keystore.Store(bufio.NewWriter(&keystoreData), password); err != nil {
        b.recorder.Eventf(bundle, corev1.EventTypeWarning, "KeyStoreError", "Could not generate keystore: %s", err)
        return false, nil, err
    }

    return updated, keystoreData.Bytes(), nil
}

// Get a reproducible certificate alias from PEM
// In our case, we will choose the fingerprint
func getCertAlias(cert ks.Certificate) (string, error) {
    c, err := x509.ParseCertificate(cert.Content)
    if err != nil {
        return "", err
    }
    return x509util.Fingerprint(c), nil
}

func (b *bundle) parsePem(ctx context.Context, log logr.Logger,
    bundle *trustapi.Bundle,
    pemData []byte) []ks.Certificate {

    var certs []ks.Certificate

    buffer := pemData
    for {
        var p *pem.Block

        p, buffer = pem.Decode(buffer)

        if p == nil {
            break
        }

        if p.Type != "CERTIFICATE" {
            b.recorder.Eventf(bundle, corev1.EventTypeWarning, "UnexpectedPEM", "Unexpected object type '%s' in PEM. Will skip.", p.Type)
            continue
        }

        certs = append(certs, ks.Certificate{
            Type: "X509",
            Content: p.Bytes,
        })
    }

    return certs
}
