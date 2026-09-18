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

package jwt

// FuzzJWTVerifyAndDecode targets JWT token parsing and validation.
// A bug here could allow authentication bypass in Google's Tink (OT0).
func FuzzJWTVerifyAndDecode(data []byte) int {
	if len(data) < 2 {
		return 0
	}

	// JSON payload olarak parse et
	_, _ = NewRawJWTFromJSON(nil, data)

	return 1
}

// FuzzJWTValidate targets JWT validator logic with fuzz-generated inputs.
func FuzzJWTValidate(data []byte) int {
	if len(data) < 4 {
		return 0
	}

	issuer := string(data[:len(data)/2])
	audience := string(data[len(data)/2:])

	validator, err := NewValidator(&ValidatorOpts{
		ExpectedIssuer:         &issuer,
		ExpectedAudience:       &audience,
		AllowMissingExpiration: true,
	})
	if err != nil {
		return 0
	}

	jwt, err := NewRawJWT(&RawJWTOptions{
		Issuer:            &issuer,
		Audiences:         []string{audience},
		WithoutExpiration: true,
	})
	if err != nil {
		return 0
	}

	_ = validator.Validate(jwt)
	return 1
}
// FuzzJWKSetToPublicKeysetHandle targets JWK format parsing.
// External key import is a common source of vulnerabilities.
func FuzzJWKSetToPublicKeysetHandle(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	_, _ = JWKSetToPublicKeysetHandle(data)
	return 1
}
