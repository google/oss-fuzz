// Copyright 2026 Google LLC
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

package jose

func FuzzJWSVerify(data []byte) int {
	msg, err := ParseSigned(string(data),
		[]SignatureAlgorithm{RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384, HS512},
	)
	if err != nil {
		return 0
	}
	_ = msg.FullSerialize()
	return 1
}
