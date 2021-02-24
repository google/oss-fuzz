package hardening

import (
	"bytes"
	"io/ioutil"
	"github.com/opencontainers/go-digest"
	_ "crypto/sha256"
)

func Fuzz(data []byte) int {
	buffer := bytes.NewBuffer(data)
	size := len(data)
	if digest.SHA256.Available() !=true {
		return -1
	}
	expectedDigest := digest.SHA256.FromBytes(buffer.Bytes())
	verifiedReader := &VerifiedReadCloser{
		Reader:         ioutil.NopCloser(buffer),
		ExpectedDigest: expectedDigest,
		ExpectedSize:   int64(size),
	}
	_, err := verifiedReader.Read(data)
	if err != nil {
		return 0
	}
	return 1
}
