package jose

import "fmt"

func FuzzJWEDecrypt(data []byte) int {
	msg, err := ParseEncrypted(string(data),
		[]KeyAlgorithm{RSA_OAEP, RSA_OAEP_256, A128KW, A256KW, DIRECT, ECDH_ES},
		[]ContentEncryption{A128GCM, A192GCM, A256GCM, A128CBC_HS256, A256CBC_HS512},
	)
	if err != nil {
		return 0
	}
	_ = fmt.Sprintf("%v", msg)
	return 1
}
