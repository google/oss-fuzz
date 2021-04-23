package semver

import (
	"bytes"
)

func FuzzCompareValidate(data []byte) int {
	vs := bytes.Split(data, []byte{0})
	if len(vs) != 2 {
		return 0
	}
	v1, err := Make(string(vs[0]))
	if err != nil {
		return 0
	}
	v1.Validate()
	v2, err := Make(string(vs[1]))
	if err != nil {
		return 0
	}
	v1.Compare(v2)

	return 1
}
