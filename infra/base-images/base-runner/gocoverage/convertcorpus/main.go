package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AdamKorcz/go-118-fuzz-build/coverage"
)

// reads all corpus files in a directory and converts
// them from libFuzzer format to native Go format.
func main() {
	if len(os.Args) != 3 {
		fmt.Println(os.Args)
		log.Fatalf("need exactly two argument")
	}
	FUZZERNAME := os.Args[1]
	CORPUS_PATH := os.Args[2]

	filepath.Walk(CORPUS_PATH, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		libFuzzerSeed, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		out := os.Getenv("OUT")
		fuzzerContents, err := os.ReadFile(filepath.Join(out, "rawfuzzers", FUZZERNAME))
		if err != nil {
			panic(err)
		}
		goSeed := coverage.ConvertLibfuzzerSeedToGoSeed(fuzzerContents, libFuzzerSeed, FUZZERNAME)
		err = os.Remove(path)
		if err != nil {
			panic(err)
		}
		f, err := os.Create(path)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		_, err = f.Write([]byte(goSeed))
		if err != nil {
			panic(err)
		}
		return nil
	})
}
