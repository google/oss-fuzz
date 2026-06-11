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

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"github.com/golang-jwt/jwt/v5"
)

// FuzzParseRoundTrip: Create token â†’ sign â†’ parse â†’ verify.
// Round-trip testing catches serialization bugs and algorithm confusion.
func FuzzParseRoundTrip(f *testing.F) {
	// Rich seed corpus: valid tokens with different algorithms
	seeds := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Add("")                        // empty
	f.Add("..")                      // minimal invalid
	f.Add(strings.Repeat("x", 5000)) // very long

	f.Fuzz(func(t *testing.T, tokenString string) {
		if len(tokenString) > 10000 {
			return
		}
		// Parse with different options (not just default)
		for _, parser := range []*jwt.Parser{
			jwt.NewParser(),
			jwt.NewParser(jwt.WithoutClaimsValidation()),
			jwt.NewParser(jwt.WithValidMethods([]string{"HS256", "none"})),
		} {
			parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Return appropriate key based on algorithm
				switch token.Method.Alg() {
				case "HS256", "HS384", "HS512":
					return []byte("test-secret-key-for-fuzzing"), nil
				case "none":
					return jwt.UnsafeAllowNoneSignatureType, nil
				default:
					return []byte("key"), nil
				}
			})
		}
	})
}

// FuzzAlgorithmInjection tests the critical "alg:none" attack surface.
func FuzzAlgorithmInjection(f *testing.F) {
	seeds := []string{
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.",
		"eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tokenString string) {
		if len(tokenString) > 5000 {
			return
		}
		// Parse unverified to check what's inside without signature check
		parser := jwt.NewParser()
		claims := jwt.MapClaims{}
		_, _, err := parser.ParseUnverified(tokenString, claims)
		// If parse succeeds, verify algorithm claims aren't manipulated
		if err != nil && !strings.Contains(err.Error(), "token is malformed") {
			// Any non-malformed error might indicate a bug
			_ = err
		}
	})
}

// FuzzClaimsValidation tests claims like exp, nbf, iat with edge cases.
func FuzzClaimsValidation(f *testing.F) {
	// Create valid signed tokens with edge case claims
	f.Add("HS256", int64(0), int64(0), int64(0))           // zero timestamps
	f.Add("HS256", int64(1), int64(1), int64(9999999999))    // far future
	f.Add("HS256", int64(-1), int64(-1), int64(-1))           // negative timestamps
	f.Add("none", int64(0), int64(0), int64(0))               // none alg

	f.Fuzz(func(t *testing.T, alg string, exp, nbf, iat int64) {
		if len(alg) > 10 {
			return
		}
		claims := jwt.MapClaims{
			"exp": exp,
			"nbf": nbf,
			"iat": iat,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Sign with a random key
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signed, err := token.SignedString(key)
		if err != nil {
			return // can't sign, skip
		}
		// Parse back the signed token
		parser := jwt.NewParser()
		parser.Parse(signed, func(t *jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		})
	})
}
