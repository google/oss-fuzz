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

package aes

import (
	"crypto/aes"
	"runtime"
	"strings"
)

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "not full block") {
			return
		} else if strings.Contains(err, "invalid buffer overlap") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzAesCipherDecrypt(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	keyIndex := int(data[0])
	lenIn := int(data[1])
	if lenIn < aes.BlockSize {
		return 0
	}
	data = data[2:]

	if (keyIndex + 5) > len(data) {
		return 0
	}
	key := data[:keyIndex]
	c, err := aes.NewCipher(key)
	if err != nil {
		return 0
	}

	dst := make([]byte, lenIn)
	src := data[keyIndex+1:]
	defer catchPanics()
	c.Decrypt(dst, src)
	return 1
}

func FuzzAesCipherEncrypt(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	keyIndex := int(data[0])
	lenIn := int(data[1])
	data = data[2:]

	if (keyIndex + 5) > len(data) {
		return 0
	}
	key := data[:keyIndex]
	c, err := aes.NewCipher(key)
	if err != nil {
		return 0
	}

	dst := make([]byte, lenIn)
	src := data[keyIndex+1:]
	defer catchPanics()
	c.Encrypt(dst, src)
	return 1
}
