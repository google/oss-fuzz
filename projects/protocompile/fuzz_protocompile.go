package protocompile

import (
	"bytes"
	"context"
	"io"
)

func FuzzProtoCompile(data []byte) int {
	compiler := &Compiler{
		Resolver: &SourceResolver{
			Accessor: func(_ string) (closer io.ReadCloser, e error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
		},
	}

	_, err := compiler.Compile(context.Background(), "test.proto")
	if err != nil {
		return 0
	}
	return 1
}
