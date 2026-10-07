// Copyright 2021 Google LLC
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

package config

import (
	"context"
	"encoding/json"
)

func FuzzConfig(data []byte) int {
	if len(data) != 32 {
		return -1
	}
	crypter := NewSymmetricCrypter(make([]byte, 32))
	_, _ = crypter.EncryptValue(context.Background(), string(data))
	_, _ = crypter.DecryptValue(context.Background(), string(data))
	return 1
}

func fuuzRoundtripKey(m Key, marshal func(v interface{}) ([]byte, error),
	unmarshal func([]byte, interface{}) error) (Key, error) {
	b, err := marshal(m)
	if err != nil {
		return Key{}, err
	}

	var newM Key
	err = unmarshal(b, &newM)
	return newM, err
}

func FuzzParseKey(data []byte) int {
	k, err := ParseKey(string(data))
	if err != nil {
		return 0
	}
	fuuzRoundtripKey(k, json.Marshal, json.Unmarshal)
	return 1
}
