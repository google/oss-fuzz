// Copyright 2024 Google LLC
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

package cert

import (
	"testing"
)

func FuzzKeyParsers(f *testing.F) {
	f.Fuzz(func(t *testing.T, parser uint8, keyData []byte) {
		switch int(parser) % 3 {
		case 0:
			ParsePrivateKeyPEM(keyData)
		case 1:
			ParsePublicKeysPEM(keyData)
		case 2:
			ParseCertsPEM(keyData)
		}
	})
}
