package jose

func FuzzJWSVerify(data []byte) int {
	msg, err := ParseSigned(string(data),
		[]SignatureAlgorithm{RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384, HS512},
	)
	if err != nil {
		return 0
	}
	_ = msg.FullSerialize()
	return 1
}
