package db

//import "github.com/gogs/internal/db"

func Fuzz(data []byte) int {
	_, err := CheckPublicKeyString(string(data))
	if err != nil {
		return 0
	}
	return 1
}
