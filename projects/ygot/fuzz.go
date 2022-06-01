// +build gofuzz

package exampleoc

func Fuzz(data []byte) int {
	nd := &Device{}
	err := Unmarshal([]byte(data), nd)
	if err != nil {
		return 0
	}
	return 1
}
