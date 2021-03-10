// +build gofuzz

package snappy

import (
	"bytes"
)

func FuzzRoundTrip(data []byte) int {
	encoded := Encode(nil, data)
	decoded, err := Decode(nil, encoded)
	if err != nil {
		panic("Error decoding snappy-encoded")
	}
	if !bytes.Equal(data, decoded) {
		panic("Different result on roundtrip encode/decode")
	}
	return 1
}

func FuzzDecode(data []byte) int {
	_, err := Decode(nil, data)
	if err != nil {
		return 0
	}
	return 1
}
