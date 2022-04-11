package fuzz

import (
	"testing"
)
func Fuzz(f *testing.F) {
	f.Fuzz(func(t *testing.T, i int) {
		return
	})
}