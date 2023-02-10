// Copyright 2022 Google LLC
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

package x509

import (
	"crypto/x509"
	"encoding/pem"
)

func FuzzParseCert(data []byte) int {
	if len(data) < 2 {
		return 1
	}
	plural := int(data[0])%2 == 0
	data = data[1:]
	if plural {
		_, _ = x509.ParseCertificates(data)
	} else {
		_, _ = x509.ParseCertificate(data)
	}
	return 1
}

func FuzzPemDecrypt(data []byte) int {
	if len(data) < 6 {
		return 0
	}
	pemDataLen := int(data[0])
	if (pemDataLen + 5) > len(data) {
		return 0
	}
	data = data[1:]
	pemData := data[:pemDataLen]
	password := data[pemDataLen+1:]
	block, _ := pem.Decode(pemData)
	if block == nil {
		return 0
	}

	_, _ = x509.DecryptPEMBlock(block, password)
	return 1
}
