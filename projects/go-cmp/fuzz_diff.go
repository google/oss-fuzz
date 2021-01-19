// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
// Modified from original file https://github.com/dvyukov/go-fuzz-corpus/blob/master/json/json.go

package cmp

import (
	"bytes"
	"encoding/json"
)

func FuzzDiff(data []byte) int {
	score := 0
	sep := bytes.IndexByte(data, 0)
	if sep < 0 {
		return 0
	}
	for _, ctor := range []func() interface{}{
		//func() interface{} { return nil },
		func() interface{} { return new([]interface{}) },
		func() interface{} { m := map[string]string{}; return &m },
		func() interface{} { m := map[string]interface{}{}; return &m },
		func() interface{} { return new(S) },
	} {
		vj := ctor()
		err := json.Unmarshal(data[:sep], vj)
		if err != nil {
			continue
		}
		vj2 := ctor()
		err = json.Unmarshal(data[sep+1:], vj)
		if err != nil {
			continue
		}
		score = 1
		Diff(vj, vj2)
	}
	return score
}

type S struct {
	A int    `json:",omitempty"`
	B string `json:"B1,omitempty"`
	C float64
	D bool
	E uint8
	F []byte
	G interface{}
	H map[string]interface{}
	I map[string]string
	J []interface{}
	K []string
	L S1
	M *S1
	N *int
	O **int
	//	P json.RawMessage
	//Q Marshaller
	R int `json:"-"`
	S int `json:",string"`
}

type S1 struct {
	A int
	B string
}
