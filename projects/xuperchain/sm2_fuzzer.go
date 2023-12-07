package sm2

func Fuzz(data []byte) int {
	_, _ = ReadPrivateKeyFromMem(data, nil)
	return 1
}
