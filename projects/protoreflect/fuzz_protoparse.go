package protoparse

import (
	"bytes"
	"io"
	"io/ioutil"
)

func FuzzProtoParse(data []byte) int {
	parser := &Parser{
		Accessor: func(_ string) (closer io.ReadCloser, e error) {
			return ioutil.NopCloser(bytes.NewReader(data)), nil
		},
	}

	_, err := parser.ParseFiles("dummy")
	if err != nil {
		return 0
	}
	return 1
}
