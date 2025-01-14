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
	"testing"
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
	priv, err := ecdsa.GenerateKey(c[cIndex], randReader)
	if err != nil {
		return 0
	}
	_, _, _ = ecdsa.Sign(randReader, priv, data[firstRandReaderLen+1:])
	return 1
}

func FuzzEcdsaVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, rand1, rand2, sig []byte, cIndex uint8) {

		cs := []elliptic.Curve{
			elliptic.P256(),
			elliptic.P224(),
			elliptic.P384(),
			elliptic.P521(),
		}
		c := int(cIndex) % len(cs)
		randReader := bytes.NewReader(rand1)
		priv, err := ecdsa.GenerateKey(cs[c], randReader)
		if err != nil {
			return
		}
		pub := priv.Public()
		ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), rand2, sig)
	})
}
