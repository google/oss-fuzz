//go:build go1.18 || go1.19 || go1.20
// +build go1.18 go1.19 go1.20

package toml

import (
	"fmt"
	"reflect"
	"strings"
)

func FuzzToml(data []byte) int {
	if strings.Contains(string(data), "nan") {
		return 0
	}

	var v interface{}
	err := Unmarshal(data, &v)
	if err != nil {
		return 0
	}

	encoded, err := Marshal(v)
	if err != nil {
		return 0
	}

	var v2 interface{}
	err = Unmarshal(encoded, &v2)
	if err != nil {
		panic(fmt.Sprintf("Failed round trip: %s", err))
	}

	if !reflect.DeepEqual(v, v2) {
		panic(fmt.Sprintf("Not equal: %#+v %#+v", v, v2))
	}

	return 1
}
