// +build gofuzz

package openapi_v2

import (
	"github.com/golang/protobuf/proto"
)

func Fuzz(data []byte) int {
	d := &Document{}
	err := proto.Unmarshal(data, d)
	//fmt.Printf("debugd %v\ndebugu %s: %#+v\n", data, err, d)
	if err != nil {
		panic("Failed to unmarshal profile")
	}
	d.ToRawInfo()
	return 0
}
