package fuzz

import (
	"context"

	"github.com/golang/protobuf/proto"

	"github.com/google/trillian"
	"github.com/google/trillian/trees"
)

func FuzzTree(data []byte) int {
	tree := &trillian.Tree{}
	err := proto.Unmarshal(data, tree)
	//fmt.Printf("debugd %v\ndebugu %s: %#+v\n", data, err, tree)
	if err != nil {
		panic("Failed to unmarshal tree")
	}

	ctx := context.Background()
	_, err = trees.Signer(ctx, tree)
	if err != nil {
		return 1
	}
	return 0
}
