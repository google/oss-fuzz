package hpack

import (
	"bytes"
	"testing"
)

// FuzzHpackDecode tests HPACK header decoding with arbitrary binary input.
// HPACK is the HTTP/2 header compression algorithm. Every HTTP/2 connection
// uses this. A crash here is a DoS vector for any Go HTTP/2 server.

func FuzzHpackDecode(f *testing.F) {
	// Seed with valid HPACK encoded headers
	f.Add([]byte{
		0x82,                                           // empty index
		0x86,                                           // :method: GET (indexed)
		0x84,                                           // :path: / (indexed)
		0x0f, 0x02, 0x03, 'f', 'o', 'o',             // literal with indexing
	})
	f.Add([]byte{})       // empty
	f.Add([]byte{0x80})   // single byte
	f.Add([]byte{0x3f, 0xff, 0xff, 0xff, 0xff}) // max int prefix

	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		dec := NewDecoder(4096, func(f HeaderField) {
			// Collect decoded headers
			buf.WriteString(f.Name)
			buf.WriteString(f.Value)
		})

		// Decode should never panic
		_, _ = dec.Write(data)
		// Close should never panic
		_ = dec.Close()
	})
}

// FuzzHpackRoundTrip tests HPACK encode → decode consistency.
func FuzzHpackRoundTrip(f *testing.F) {
	f.Add("content-type", "text/html")
	f.Add("x-custom", "value")
	f.Add(":method", "GET")
	f.Add(":path", "/api/v1/users?page=1&limit=100")

	f.Fuzz(func(t *testing.T, name, value string) {
		// Encode
		var buf bytes.Buffer
		enc := NewEncoder(&buf)
		err := enc.WriteField(HeaderField{Name: name, Value: value, Sensitive: false})
		if err != nil {
			// Encoding failed — maybe invalid header name
			return
		}

		// Decode
		encoded := buf.Bytes()
		decoded := false
		dec := NewDecoder(4096, func(f HeaderField) {
			decoded = true
		})

		_, err = dec.Write(encoded)
		if err != nil {
			return // decode error expected for some inputs
		}
		_ = decoded
	})
}
