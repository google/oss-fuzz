package models

func FuzzFill(data []byte) int {
	if len(data)<3 {
		return -1
	}
	if !IsDivisibleBy(len(data), 2) {
		return -1
	}
	d := &DhcpOption{Code: data[0]}
	err := d.Fill(string(data))
	if err != nil {
		return 0
	}
	return 1
}
