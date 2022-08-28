package toml

func FuzzToml(data []byte) int {
	if len(data) >= 10240 {
		return 0
	}

	var v interface{}
	err := Unmarshal(data, &v)
	if err != nil {
		return 0
	}

	_, err = Marshal(v)
	if err != nil {
		return 0
	}

	return 1
}
