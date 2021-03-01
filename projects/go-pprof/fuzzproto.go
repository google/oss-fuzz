package fuzzproto

import (
	"github.com/google/pprof/profile"
)

func Fuzz(data []byte) int {
	prof, err := profile.ParseUncompressed(data)
	if err != nil {
		return 1
		//panic("Failed to unmarshal profile")
	}
	prof.CheckValid()
	return 0
}
