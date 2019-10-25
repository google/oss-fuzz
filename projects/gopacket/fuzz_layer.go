// Copyright 2019 Catena cyber All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

var fuzzOpts = gopacket.DecodeOptions{
	Lazy:                     false,
	NoCopy:                   true,
	SkipDecodeRecovery:       true,
	DecodeStreamsAsDatagrams: true,
}

func FuzzLayer(data []byte) int {
	if len(data) < 2 {
		return 1
	}
	startLayer := binary.BigEndian.Uint16(data[:2])
	p := gopacket.NewPacket(data[2:], gopacket.LayerType(startLayer), fuzzOpts)
	for _, l := range p.Layers() {
		gopacket.LayerString(l)
	}
	if p.ErrorLayer() != nil {
		return 0
	}
	return 1
}
