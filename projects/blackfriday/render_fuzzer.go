package blackfriday

func Fuzz(data []byte) int {
	Run(data)
	return 0
}
