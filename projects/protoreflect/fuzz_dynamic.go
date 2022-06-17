package proto_decoder

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/builder"
	"github.com/jhump/protoreflect/dynamic"
)

func Fuzz(data []byte) int {
	d, err := desc.LoadMessageDescriptorForMessage(&empty.Empty{})
	if err != nil {
		panic(err)
	}
	mb, err := builder.FromMessage(d)
	if err != nil {
		panic(err)
	}

	msg, err := mb.Build()
	if err != nil {
		panic(err)
	}

	decoded := dynamic.NewMessage(msg)
	err = proto.Unmarshal(data, decoded)
	if err != nil {
		return 0
	}

	return 1
}
