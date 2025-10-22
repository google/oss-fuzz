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

package dsa

import (
	"bytes"
	"crypto/dsa"
	"math/big"
	"testing"
)

func FuzzDsaVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, data1, data2, data3 []byte, s1, s2 string, s uint8) {
		bi1, ok := new(big.Int).SetString(s1, 16)
		bi2, ok2 := new(big.Int).SetString(s2, 16)
		if !ok || !ok2 {
			return
		}
		var priv dsa.PrivateKey
		params := &priv.Parameters
		sizes := []dsa.ParameterSizes{
			dsa.L1024N160,
			dsa.L2048N224,
			dsa.L2048N256,
			dsa.L3072N256,
		}
		err := dsa.GenerateParameters(params, bytes.NewReader(data1), sizes[int(s)%len(sizes)])
		if err != nil {
			return
		}
		err = dsa.GenerateKey(&priv, bytes.NewReader(data2))
		if err != nil {
			return
		}
		dsa.Verify(&priv.PublicKey, data3, bi1, bi2)
	})
}

func FuzzDsaSign(f *testing.F) {
	f.Fuzz(func(t *testing.T, data1, data2, data3, data4 []byte, s uint8) {
		var priv dsa.PrivateKey
		params := &priv.Parameters
		sizes := []dsa.ParameterSizes{
			dsa.L1024N160,
			dsa.L2048N224,
			dsa.L2048N256,
			dsa.L3072N256,
		}
		err := dsa.GenerateParameters(params, bytes.NewReader(data1), sizes[int(s)%len(sizes)])
		if err != nil {
			return
		}
		err = dsa.GenerateKey(&priv, bytes.NewReader(data2))
		if err != nil {
			return
		}
		dsa.Sign(bytes.NewReader(data3), &priv, data4)
	})
}
