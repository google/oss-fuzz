package gonidsfuzz

import (
	"github.com/google/gonids"
)

func Fuzz(data []byte) int {
	r, err := gonids.ParseRule(string(data))
	if err != nil {
		// Handle parse error
		return 0
	}
	r.OptimizeHTTP()
	return 1
}
