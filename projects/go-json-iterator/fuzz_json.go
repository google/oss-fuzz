// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
// Modified from original file https://github.com/dvyukov/go-fuzz-corpus/blob/master/json/json.go

package jsoniter

import (
	"encoding/json"
	"fmt"
	"reflect"
)

func Fuzz(data []byte) int {
	score := 0
	for _, ctor := range []func() interface{}{
		//func() interface{} { return nil },
		func() interface{} { return new([]interface{}) },
		func() interface{} { m := map[string]string{}; return &m },
		func() interface{} { m := map[string]interface{}{}; return &m },
		func() interface{} { return new(S) },
	} {
		v := ctor()
		if ConfigCompatibleWithStandardLibrary.Unmarshal(data, v) != nil {
			continue
		}
		score = 1
		vj := ctor()
		err := json.Unmarshal(data, vj)
		if err != nil {
			panic(err)
		}
		if !reflect.DeepEqual(v, vj) {
			fmt.Printf("v0: %#v\n", v)
			fmt.Printf("v1: %#v\n", vj)
			panic("not equal")
		}

		data1, err := ConfigCompatibleWithStandardLibrary.Marshal(v)
		if err != nil {
			panic(err)
		}
		v1 := ctor()
		if ConfigCompatibleWithStandardLibrary.Unmarshal(data1, v1) != nil {
			continue
		}
		if !reflect.DeepEqual(v, v1) {
			fmt.Printf("v0: %#v\n", v)
			fmt.Printf("v1: %#v\n", v1)
			panic("not equal")
		}
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
	Q Marshaller
	R int `json:"-"`
	S int `json:",string"`
}

type S1 struct {
	A int
	B string
}

type Marshaller struct {
	v string
}

func (m *Marshaller) MarshalJSON() ([]byte, error) {
	return ConfigCompatibleWithStandardLibrary.Marshal(m.v)
}

func (m *Marshaller) UnmarshalJSON(data []byte) error {
	return ConfigCompatibleWithStandardLibrary.Unmarshal(data, &m.v)
}
