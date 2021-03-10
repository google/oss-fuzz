// +build traefikfuzz

package rules

func Fuzz(data []byte) int {
	parser, err := newParser()
	if err != nil {
		return -1
	}
	_, _ = parser.Parse(string(data))
	return 1
}
