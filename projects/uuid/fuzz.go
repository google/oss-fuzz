package fuzz

import "github.com/google/uuid"

func Fuzz(data []byte) int {
	_, err := uuid.Parse(string(data))
	if err != nil {
		return 0
	}
	return 1
}
