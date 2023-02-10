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

package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
)

func FuzzEcdsaSign(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	c := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P224(),
		elliptic.P384(),
		elliptic.P521(),
	}
	cIndex := int(data[0] % 4)
	firstRandReaderLen := int(data[1])
	data = data[2:]
	if (firstRandReaderLen + 3) > len(data) {
		return 0
	}
	randReader := bytes.NewReader(data[:firstRandReaderLen])
	priv, _ := ecdsa.GenerateKey(c[cIndex], randReader)
	_, _, _ = ecdsa.Sign(randReader, priv, data[firstRandReaderLen+1:])
	return 1
}
