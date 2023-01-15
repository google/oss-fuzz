package toml

import "bytes"

func FuzzToml(data []byte) int {

	if len(data) >= 10240 {
		return 0
	}

	buf := make([]byte, 0, 2048)

	var m interface{}
	_, err := Decode(string(data), &m)
	if err != nil {
		return 0
	}

	err = NewEncoder(bytes.NewBuffer(buf)).Encode(m)
	if err != nil {
		return 0
	}

	return 1
}
