package mxj

func FuzzMapXml(data []byte) int {
	m, err := NewMapXml(data)
	if err != nil {
		return 0
	}

	_, err = m.Xml()
	if err != nil {
		return 0
	}

	return 1
}
