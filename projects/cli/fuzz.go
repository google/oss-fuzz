package fuzz

import (
	"github.com/cli/cli/internal/config"
	"os"
)

func Fuzz(data []byte) int {
	f, err := os.Create("config.yml")
	if err != nil {
		return -1
	}
	defer f.Close()
	defer os.Remove("config.yml")
	_, err = f.Write(data)
	if err != nil {
		return -1
	}
	_, err = config.ParseConfig("config.yml")
	if err != nil {
		return 0
	}
	return 1
}
