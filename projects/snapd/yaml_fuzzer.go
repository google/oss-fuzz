package fuzz

import "github.com/snapcore/snapd/snap"

func FuzzInfo(data []byte) int {
	_, err := snap.InfoFromSnapYaml(data)
	if err != nil {
		return 0
	}
	return 1
}
