package jose

func FuzzJWTParse(data []byte) int {
	msg, err := ParseSigned(string(data),
		[]SignatureAlgorithm{RS256, ES256, HS256},
	)
	if err != nil {
		return 0
	}
	_, _ = msg.CompactSerialize()
	return 1
}
