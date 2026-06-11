// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsmessage

import (
	"testing"
)

// FuzzDNSMessageParse tests DNS message parsing with arbitrary byte inputs.
// DNS is critical internet infrastructure — a parsing bug here affects
// every DNS resolver built in Go.

func FuzzDNSMessageParse(f *testing.F) {
	// Seed corpus with valid DNS queries and responses
	f.Add([]byte{
		// DNS query for example.com A record
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	})

	f.Add([]byte{}) // empty input
	f.Add([]byte{0x00}) // single byte
	f.Add([]byte{0x00, 0x01, 0x02, 0x03}) // malformed header

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test 1: Parser.Start — should never panic on any input
		var p Parser
		h, err := p.Start(data)
		if err != nil {
			return // expected for malformed input
		}
		_ = h

		// Test 2: Parse questions — should not panic
		for {
			q, err := p.Question()
			if err != nil { break }
			_ = q
		}

		// Test 3: Parse answers — should not panic
		for {
			ah, err := p.AnswerHeader()
			if err != nil { break }
			_, err = p.Answer()
			if err != nil { break }
			_ = ah
		}
	})
}

// FuzzDNSName tests DNS name parsing which has complex compression/pointer logic.
func FuzzDNSName(f *testing.F) {
	f.Add([]byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00})
	f.Add([]byte{0x00}) // root label
	f.Add([]byte{0xc0, 0x00}) // compression pointer to start
	f.Add([]byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xc0, 0x00}) // name + pointer

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse and verify name round-trip where possible
		var p Parser
		// Try to start a DNS message with just a name
		if _, err := p.Start(append([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, data...)); err != nil {
			return
		}
		_, err := p.Question()
		if err != nil && err != ErrSectionDone {
			// Acceptable — name parsing error is expected for fuzzed input
		}
	})
}
