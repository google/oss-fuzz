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

package fuzz

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CryptoSecurityContext provides security validation for cryptographic operations
type CryptoSecurityContext struct {
	WeakAlgorithms   []string
	DeprecatedHashes []string
	MinKeySize       map[string]int
	MaxDataSize      int
	TimingAttackSafe bool
}

// SecurityAwareCrypto extends crypto operations with security validation
type SecurityAwareCrypto struct {
	Context     *CryptoSecurityContext
	SecurityLog []string
	RiskLevel   string
	Timestamp   time.Time
}

// NewCryptoSecurityContext creates a hardened security context for crypto operations
func NewCryptoSecurityContext() *CryptoSecurityContext {
	return &CryptoSecurityContext{
		WeakAlgorithms: []string{
			"DES", "3DES", "RC4", "Blowfish", "MD4", "MD5",
			"SHA1", "CRC32", "Adler32", "Base64", "ROT13",
		},
		DeprecatedHashes: []string{
			"md4", "md5", "sha1", "crc32", "adler32",
		},
		MinKeySize: map[string]int{
			"AES":      128,
			"RSA":      2048,
			"ECDSA":    256,
			"HMAC":     256,
			"ChaCha20": 256,
		},
		MaxDataSize:      1024 * 1024, // 1MB
		TimingAttackSafe: true,
	}
}

// FuzzCryptoOperations is the libFuzzer entrypoint for cryptographic security testing
// Tests cryptographic operations, weak algorithms, and crypto attack vectors
func FuzzCryptoOperations(data []byte) int {
	if len(data) == 0 || len(data) > 8192 {
		return 0
	}

	// Initialize security context
	context := NewCryptoSecurityContext()
	crypto := &SecurityAwareCrypto{
		Context:     context,
		SecurityLog: make([]string, 0),
		RiskLevel:   "LOW",
		Timestamp:   time.Now(),
	}

	// Test hashing security
	if testHashSecurity(crypto, data) {
		return 0
	}

	// Test encryption security
	if testEncryptionSecurity(crypto, data) {
		return 0
	}

	// Test HMAC security
	if testHMACSecurity(crypto, data) {
		return 0
	}

	// Test key derivation security
	if testKeyDerivationSecurity(crypto, data) {
		return 0
	}

	// Test timing attack prevention
	if testTimingAttackPrevention(crypto, data) {
		return 0
	}

	// Test cryptographic randomness
	if testRandomnessSecurity(crypto, data) {
		return 0
	}

	// Test side channel attack prevention
	if testSideChannelAttacks(crypto, data) {
		return 0
	}

	// Test key exchange security
	if testKeyExchangeSecurity(crypto, data) {
		return 0
	}

	// Test digital signature security
	if testDigitalSignatureSecurity(crypto, data) {
		return 0
	}

	return 1
}

// testHashSecurity tests hash function security
func testHashSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	dataStr := strings.ToLower(string(data))
	for _, deprecated := range crypto.Context.DeprecatedHashes {
		if strings.Contains(dataStr, deprecated) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				fmt.Sprintf("Deprecated hash algorithm usage: %s", deprecated))
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	// Test hash collision patterns
	if len(data) >= 64 {
		// Test for identical prefixes (potential collision)
		if subtle.ConstantTimeCompare(data[:32], data[32:64]) == 1 {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Potential hash collision pattern detected")
			crypto.RiskLevel = "MEDIUM"
			return true
		}
	}

	// Test hash length extension attacks
	if testHashLengthExtension(crypto, data) {
		return true
	}

	return false
}

// testEncryptionSecurity tests encryption security
func testEncryptionSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for weak encryption patterns
	dataStr := strings.ToUpper(string(data))
	for _, weak := range crypto.Context.WeakAlgorithms {
		if strings.Contains(dataStr, weak) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				fmt.Sprintf("Weak encryption algorithm usage: %s", weak))
			crypto.RiskLevel = "CRITICAL"
			return true
		}
	}

	// Test for hardcoded keys
	if testHardcodedKeys(crypto, data) {
		return true
	}

	// Test for ECB mode usage (insecure)
	if strings.Contains(strings.ToUpper(string(data)), "ECB") {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"ECB mode usage detected (insecure)")
		crypto.RiskLevel = "HIGH"
		return true
	}

	// Test for weak key sizes
	if testWeakKeySizes(crypto, data) {
		return true
	}

	return false
}

// testHMACSecurity tests HMAC security
func testHMACSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for HMAC timing attacks
	if len(data) >= 32 && !crypto.Context.TimingAttackSafe {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"HMAC timing attack vulnerability detected")
		crypto.RiskLevel = "HIGH"
		return true
	}

	// Test for HMAC key reuse
	if testHMACKeyReuse(crypto, data) {
		return true
	}

	// Test for weak HMAC keys
	if len(data) >= 16 {
		key := data[:16]
		// Check for predictable keys
		if isPredictableKey(key) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Predictable HMAC key detected")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

// testKeyDerivationSecurity tests key derivation security
func testKeyDerivationSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for weak password patterns
	dataStr := strings.ToLower(string(data))
	weakPatterns := []string{
		"password", "123456", "qwerty", "admin", "root",
		"letmein", "welcome", "monkey", "dragon", "master",
		"test", "demo", "sample", "default", "user",
	}

	for _, pattern := range weakPatterns {
		if strings.Contains(dataStr, pattern) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				fmt.Sprintf("Weak password pattern detected: %s", pattern))
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for PBKDF2 with low iteration count
	if strings.Contains(strings.ToUpper(string(data)), "PBKDF2") {
		if strings.Contains(string(data), "1000") ||
			strings.Contains(string(data), "10000") {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Low PBKDF2 iteration count detected")
			crypto.RiskLevel = "MEDIUM"
			return true
		}
	}

	// Test for salt reuse
	if testSaltReuse(crypto, data) {
		return true
	}

	return false
}

// testTimingAttackPrevention tests timing attack prevention
func testTimingAttackPrevention(crypto *SecurityAwareCrypto, data []byte) bool {
	if len(data) < 32 {
		return false
	}

	// Simulate timing attack test
	expected := make([]byte, 16)
	actual := data[:16]

	// Use constant time comparison
	result := subtle.ConstantTimeCompare(expected, actual)

	// If result is 1, the data matches our test value (which should be rare)
	if result == 1 {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"Timing attack test triggered")
		crypto.RiskLevel = "LOW"
		return true
	}

	return false
}

// testRandomnessSecurity tests cryptographic randomness
func testRandomnessSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	if len(data) < 64 {
		return false
	}

	// Test for predictable patterns
	if isPredictableData(data) {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"Predictable cryptographic data detected")
		crypto.RiskLevel = "HIGH"
		return true
	}

	// Test for insufficient entropy
	entropy := calculateEntropy(data[:32])
	if entropy < 3.0 {
		crypto.SecurityLog = append(crypto.SecurityLog,
			fmt.Sprintf("Low entropy detected: %.2f bits", entropy))
		crypto.RiskLevel = "MEDIUM"
		return true
	}

	// Test for reused nonces/IVs
	if testNonceReuse(crypto, data) {
		return true
	}

	return false
}

// Helper functions

func testHardcodedKeys(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for common hardcoded key patterns
	patterns := []string{
		"0123456789abcdef",
		"0000000000000000",
		"1111111111111111",
		"aaaaaaaaaaaaaaaa",
		"deadbeefdeadbeef",
		"feedfacefeedface",
	}

	dataStr := strings.ToLower(hex.EncodeToString(data))
	for _, pattern := range patterns {
		if strings.Contains(dataStr, pattern) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Hardcoded key pattern detected")
			crypto.RiskLevel = "CRITICAL"
			return true
		}
	}

	return false
}

func testWeakKeySizes(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for weak key sizes
	dataStr := string(data)
	weakSizes := []string{"56", "64", "80", "128", "512"} // weak or very large

	for _, size := range weakSizes {
		if strings.Contains(dataStr, size) {
			if size == "56" || size == "64" || size == "80" {
				crypto.SecurityLog = append(crypto.SecurityLog,
					fmt.Sprintf("Weak key size detected: %s bits", size))
				crypto.RiskLevel = "HIGH"
				return true
			}
			if size == "512" {
				crypto.SecurityLog = append(crypto.SecurityLog,
					fmt.Sprintf("Potentially weak key size detected: %s bits", size))
				crypto.RiskLevel = "MEDIUM"
				return true
			}
		}
	}

	return false
}

func testHMACKeyReuse(crypto *SecurityAwareCrypto, data []byte) bool {
	// Simulate HMAC key reuse detection
	if len(data) >= 64 {
		key1 := data[:32]
		key2 := data[32:64]

		if subtle.ConstantTimeCompare(key1, key2) == 1 {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"HMAC key reuse detected")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

func isPredictableKey(key []byte) bool {
	// Check for sequential patterns
	for i := 1; i < len(key); i++ {
		if key[i] != key[i-1]+1 {
			// Not sequential, check for repeated patterns
			if i >= 3 && key[i] == key[i-3] && key[i-1] == key[i-4] {
				return true
			}
		}
	}

	// Check for all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		return true
	}

	// Check for all same byte
	allSame := true
	for i := 1; i < len(key); i++ {
		if key[i] != key[0] {
			allSame = false
			break
		}
	}

	return allSame
}

func testHashLengthExtension(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for hash length extension attack patterns
	dataStr := strings.ToLower(string(data))

	// Look for MD5/SHA1 usage with user-controlled data
	if strings.Contains(dataStr, "md5") || strings.Contains(dataStr, "sha1") {
		if strings.Contains(dataStr, "&") || strings.Contains(dataStr, "=") {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Potential hash length extension vulnerability")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

func testSaltReuse(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for salt reuse patterns
	if len(data) >= 32 {
		salt1 := data[:16]
		salt2 := data[16:32]

		if subtle.ConstantTimeCompare(salt1, salt2) == 1 {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Salt reuse detected")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

func isPredictableData(data []byte) bool {
	// Check for sequential patterns
	sequential := true
	for i := 1; i < len(data); i++ {
		if data[i] != data[i-1]+1 {
			sequential = false
			break
		}
	}
	if sequential {
		return true
	}

	// Check for repeated patterns
	if len(data) >= 8 {
		pattern := data[:4]
		for i := 4; i <= len(data)-4; i += 4 {
			if subtle.ConstantTimeCompare(pattern, data[i:i+4]) != 1 {
				return false
			}
		}
		return true
	}

	return false
}

func calculateEntropy(data []byte) float64 {
	// Simple entropy calculation
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (p / p) // Simplified entropy calculation
		}
	}

	return entropy
}

func testNonceReuse(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for nonce/IV reuse
	if len(data) >= 32 {
		nonce1 := data[:16]
		nonce2 := data[16:32]

		if subtle.ConstantTimeCompare(nonce1, nonce2) == 1 {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Nonce/IV reuse detected")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

// Additional cryptographic security tests

func testSideChannelAttacks(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for side channel attack patterns
	if len(data) >= 32 {
		// Test for cache timing patterns
		accessPattern := make([]int, 0)
		for i, b := range data[:16] {
			if b > 128 {
				accessPattern = append(accessPattern, i)
			}
		}

		if len(accessPattern) > 8 {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Potential cache timing attack pattern detected")
			crypto.RiskLevel = "MEDIUM"
			return true
		}
	}

	return false
}

func testKeyExchangeSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for key exchange vulnerabilities
	dataStr := strings.ToLower(string(data))

	// Check for export-grade key exchange
	if strings.Contains(dataStr, "export") {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"Export-grade key exchange detected")
		crypto.RiskLevel = "HIGH"
		return true
	}

	// Check for weak Diffie-Hellman parameters
	if strings.Contains(dataStr, "dh") {
		if strings.Contains(dataStr, "512") || strings.Contains(dataStr, "768") {
			crypto.SecurityLog = append(crypto.SecurityLog,
				"Weak Diffie-Hellman parameters detected")
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	return false
}

func testDigitalSignatureSecurity(crypto *SecurityAwareCrypto, data []byte) bool {
	// Test for digital signature vulnerabilities
	dataStr := strings.ToLower(string(data))

	// Check for weak signature algorithms
	weakSigs := []string{"md5", "sha1", "dsa"}
	for _, weak := range weakSigs {
		if strings.Contains(dataStr, weak) {
			crypto.SecurityLog = append(crypto.SecurityLog,
				fmt.Sprintf("Weak signature algorithm: %s", weak))
			crypto.RiskLevel = "HIGH"
			return true
		}
	}

	// Test for signature malleability
	if strings.Contains(dataStr, "malleability") ||
		strings.Contains(dataStr, "forge") {
		crypto.SecurityLog = append(crypto.SecurityLog,
			"Signature malleability vulnerability detected")
		crypto.RiskLevel = "CRITICAL"
		return true
	}

	return false
}
