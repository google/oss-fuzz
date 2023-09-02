package dockerutil

import (
	"bytes"
)

func Fuzz(data []byte) int {
	r := bytes.NewReader(data)
	_, _, err := ParseManifestV2(r)
	if err != nil {
		return 0
	}
	return 1
}
