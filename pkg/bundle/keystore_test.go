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
    "testing"

    apiequality "k8s.io/apimachinery/pkg/api/equality"
    "github.com/stretchr/testify/assert"
    corev1 "k8s.io/api/core/v1"
    fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
    "k8s.io/apimachinery/pkg/runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "k8s.io/client-go/tools/record"
    "k8s.io/klog/v2/klogr"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    // ks "github.com/pavlo-v-chernykh/keystore-go/v4"

    trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
    "github.com/cert-manager/trust-manager/test/dummy"
)

func Test_parsePem(t *testing.T) {


    t.Run("Identify the correct number of certificates", func(t *testing.T) {
        clientBuilder := fakeclient.NewClientBuilder().
            WithScheme(trustapi.GlobalScheme)
        fakeclient := clientBuilder.Build()
        fakerecorder := record.NewFakeRecorder(1)

        pemData := dummy.DefaultJoinedCerts()
        bd := &trustapi.Bundle{
            ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle"},
            Spec: trustapi.BundleSpec{Target: trustapi.BundleTarget{
                ConfigMap: &trustapi.KeySelector{Key: "ca.crt"},
                KeyStore: &trustapi.KeyStoreSelector{Key: "ca.jks", Password: "changeit"},
            }},
        }
        b := &bundle{targetDirectClient: fakeclient, recorder: fakerecorder}
        certs := b.parsePem(context.TODO(), klogr.New(), bd, []byte(pemData))
        assert.Equal(t, len(certs), 3)

        var event string
        select {
        case event = <-fakerecorder.Events:
        default:
        }

        // Ensure no event happened
        assert.Equal(t, event, "")
    })

}

func Test_syncKeyStoreStatus(t *testing.T) {

    const(
        trustNamespace = "trust-namespace"
    )

    var(
        namespaces = []runtime.Object{
            &corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: trustNamespace}},
            &corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-1"}},
            &corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-2"}},
        }
    )

    tests := map[string]struct{
        pemData []byte
        target *trustapi.BundleTarget
        expUpdate bool
        existingObjects []runtime.Object
        expObjects []runtime.Object
    }{
        "if no bundle exists, should return nothing": {
            pemData: []byte(dummy.TestCertificate1),
            target: &trustapi.BundleTarget{
                ConfigMap: &trustapi.KeySelector{Key: "ca.crt"},
                KeyStore: &trustapi.KeyStoreSelector{Key: "ca.jks", Password: "changeit"},
            },
            expUpdate: false,
            expObjects: append(namespaces),
            existingObjects: append(namespaces),
        },
    }

    for name, test := range tests {
        t.Run(name, func(t *testing.T) {
            fakeclient := fakeclient.NewClientBuilder().
                WithScheme(trustapi.GlobalScheme).
                WithRuntimeObjects(test.existingObjects...).
                Build()
            fakerecorder := record.NewFakeRecorder(1)

            bd := &trustapi.Bundle{
                ObjectMeta: metav1.ObjectMeta{Name: "ca-bundle"},
                Spec: trustapi.BundleSpec{Target: *test.target},
            }
            b := &bundle{targetDirectClient: fakeclient, recorder: fakerecorder}

            updated, err := b.syncKeyStore(context.TODO(), klogr.New(), bd, test.pemData)
            if err != nil {
                t.Errorf("Unexpected error: %s", err)
            }

            assert.Equal(t, updated, test.expUpdate)

            // Ensure the status is not nil
            assert.NotEqual(t, len(bd.Status.KeyStore), 0)

            for _, expectedObject := range test.expObjects {
                expObj := expectedObject.(client.Object)
                var actual client.Object
                switch expObj.(type) {
                case *corev1.Secret:
                    actual = &corev1.Secret{}
                case *corev1.ConfigMap:
                    actual = &corev1.ConfigMap{}
                case *corev1.Namespace:
                    actual = &corev1.Namespace{}
                case *trustapi.Bundle:
                    actual = &trustapi.Bundle{}
                default:
                    t.Errorf("unexpected object kind in expected: %#+v", expObj)
                }

                err := fakeclient.Get(context.TODO(), client.ObjectKeyFromObject(expObj), actual)
                assert.NoError(t, err)
                if !apiequality.Semantic.DeepEqual(expObj, actual) {
                    t.Errorf("unexpected expected object\nexp=%#+v\ngot=%#+v", expObj, actual)
                }
            }

        })
    }

}
