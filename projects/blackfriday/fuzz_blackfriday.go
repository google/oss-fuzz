package blackfriday

func Fuzz(data []byte) int {
	output := blackfriday.Run(data)
}