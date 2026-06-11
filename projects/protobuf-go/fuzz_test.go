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

package protowire

import (
	"testing"
)

// FuzzConsumeTag tests protobuf wire-format tag parsing with arbitrary bytes.
// Every protobuf message in existence uses this wire format. A parsing bug
// here affects EVERY Go service using protobuf — which is essentially all of them.

func FuzzConsumeTag(f *testing.F) {
	f.Add([]byte{0x08, 0x01})            // field 1, varint, value 1
	f.Add([]byte{0x12, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g'}) // field 2, LEN
	f.Add([]byte{})                        // empty
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // max varint
	f.Add([]byte{0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}) // max varint value

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test 1: ConsumeTag — should never panic
		for len(data) > 0 {
			_, _, n := ConsumeTag(data)
			if n < 0 {
				break // ParseError
			}
			data = data[n:]
		}

		// Test 2: ConsumeVarint — should never panic
		data2 := make([]byte, len(data))
		copy(data2, data)
		for len(data2) > 0 {
			_, n := ConsumeVarint(data2)
			if n < 0 {
				break
			}
			data2 = data2[n:]
		}
	})
}

// FuzzWireRoundTrip tests protobuf wire encoding → decoding consistency.
// Encoded data should decode back to the same values.

func FuzzWireRoundTrip(f *testing.F) {
	// Seed with valid field numbers and types
	f.Add(uint32(1), uint32(0))  // field 1, varint
	f.Add(uint32(2), uint32(2))  // field 2, LEN
	f.Add(uint32(5), uint32(5))  // field 5, fixed32

	f.Fuzz(func(t *testing.T, fieldNum, wireType uint32) {
		// Normalize to valid protobuf field numbers (1 to 2^29-1)
		num := Number(1 + (fieldNum % ((1 << 29) - 1)))
		typ := Type(wireType % 7) // 0-6 are valid wire types

		// Encode tag
		var buf []byte
		buf = AppendTag(buf, num, typ)

		// Decode tag
		decodedNum, decodedType, n := ConsumeTag(buf)
		if n < 0 {
			t.Errorf("failed to decode tag we just encoded: num=%d typ=%d buf=%x", num, typ, buf)
			return
		}

		// Verify round-trip
		if decodedNum != num || decodedType != typ {
			t.Errorf("round-trip mismatch: (%d,%d) → (%d,%d)", num, typ, decodedNum, decodedType)
		}
	})
}

// FuzzVarintRoundTrip tests varint encoding → decoding.
func FuzzVarintRoundTrip(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(127))
	f.Add(uint64(128))
	f.Add(uint64(1 << 63 - 1)) // max uint64/2
	f.Add(uint64(1<<64 - 1))    // max uint64

	f.Fuzz(func(t *testing.T, val uint64) {
		// Encode
		buf := AppendVarint(nil, val)

		// Decode
		decoded, n := ConsumeVarint(buf)
		if n < 0 {
			t.Errorf("failed to decode varint we just encoded: val=%d buf=%x", val, buf)
			return
		}

		// Verify round-trip
		if decoded != val {
			t.Errorf("varint round-trip mismatch: %d → %x → %d", val, buf, decoded)
		}
	})
}

// FuzzConsumeField tests field consumption which combines tag + value parsing.
func FuzzConsumeField(f *testing.F) {
	f.Add([]byte{0x08, 0x2a})                         // field 1, varint 42
	f.Add([]byte{0x12, 0x03, 0x61, 0x62, 0x63})      // field 2, LEN 3, "abc"
	f.Add([]byte{0x1a, 0x04, 0x00, 0x00, 0x00, 0x00}) // field 3, LEN 4, zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		// ConsumeTag + ConsumeFieldValue should not panic
		for len(data) > 0 {
			num, typ, tagLen := ConsumeTag(data)
			if tagLen < 0 {
				break
			}
			data = data[tagLen:]

			valLen := ConsumeFieldValue(num, typ, data)
			if valLen < 0 {
				break
			}
			data = data[valLen:]
		}
	})
}
