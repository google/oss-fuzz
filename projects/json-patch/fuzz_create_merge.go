package jsonpatch

import (
	"bytes"
)

func FuzzCreateMerge(data []byte) int {
	s := bytes.Split(data, []byte{0})
	if len(s) != 3 {
		return 0
	}
	original := s[0]
	target := s[1]
	alternative := s[2]

	patch, err := CreateMergePatch(original, target)
	if err != nil {
		return 0
	}
	_, err = MergePatch(alternative, patch)
	if err != nil {
		return 0
	}

	return 1
}
