package peer

import (
	"testing"
	"log"
)

func FuzzEncodeDecodeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var id ID
		if err := id.UnmarshalText(data); err == nil {
			encoded := Encode(id)
			id2, err := Decode(encoded)
			if err != nil {
				log.Print(err)
				t.Fatalf("Decoding an encoded ID failed")
			}
			if id != id2 {
				t.Fatalf("Decoded ID does not match encoded ID")
			}
		}
	})
}
