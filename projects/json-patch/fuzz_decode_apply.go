package jsonpatch

import (
	"bytes"
)

func FuzzDecodeApply(data []byte) int {
	s := bytes.Split(data, []byte{0})
	if len(s) != 2 {
		return 0
	}
	patchJSON := s[0]
	original := s[1]

	patch, err := DecodePatch(patchJSON)
	if err != nil {
		return 0
	}

	_, err = patch.Apply(original)
	if err != nil {
		return 0
	}
	return 1
}
