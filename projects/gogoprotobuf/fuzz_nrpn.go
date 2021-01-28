package fuzztests

import (
	"fmt"
	"github.com/gogo/protobuf/proto"
)

func FuzzNinRepPackedNative(input []byte) int {
	msg := &NinRepPackedNative{}
	if err := proto.Unmarshal(input, msg); err != nil {
		return 0
	}
	output, err := proto.Marshal(msg)
	if err != nil {
		panic(fmt.Sprintf("marshal failed %s", err))
	}
	if len(input) != len(output) {
		panic(fmt.Sprintf("expected %#v got %#v for %#+v", input, output, msg))
	}
	return 1
}
