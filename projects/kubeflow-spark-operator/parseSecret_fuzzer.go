// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package certificate

import (
	"testing"

	"github.com/kubeflow/spark-operator/v2/pkg/common"
	corev1 "k8s.io/api/core/v1"
)

func FuzzParseCertManagerSecret(f *testing.F) {
	f.Fuzz(func(t *testing.T, input1, input2, input3 []byte) {
		cp := &Provider{}
		cp.parseCertManagerSecret(&corev1.Secret{
			Data: map[string][]byte{
				common.CACert:  input1,
				common.TLSCert: input2,
				common.TLSKey:  input3,
			},
		})
	})
}

func FuzzParseInternalCertSecret(f *testing.F) {
	f.Fuzz(func(t *testing.T, input1, input2, input3, input4 []byte) {
		cp := &Provider{}
		cp.parseInternalCertSecret(&corev1.Secret{
			Data: map[string][]byte{
				common.CACertPem:     input1,
				common.CAKeyPem:      input2,
				common.ServerCertPem: input3,
				common.ServerKeyPem:  input4,
			},
		})
	})
}
