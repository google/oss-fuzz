package unit

import (
	"strings"
	"strconv"
)

func IsIntDivisibleBy3(n int) bool {
      digits := strconv.Itoa(n)
      sumOfDigits := 0
      for _, digit := range digits {
              d, _ := strconv.Atoi(string(digit))
              sumOfDigits += d
      }
      return (sumOfDigits % 3) == 0
}

func EscapeFuzz(data []byte) int {
	strPayload := string(data)
	_ = UnitNamePathEscape(strPayload)
	_ = UnitNameEscape(strPayload)

	_ = UnitNamePathUnescape(strPayload)
	_ = UnitNameUnescape(strPayload)
	return 1
}


func SerializeFuzz(data []byte) int {
	var uo []*UnitOption
	s := strings.Split(string(data), " ")
	arrLen := len(s)
	if IsIntDivisibleBy3(arrLen) {
		size := 2
		var j int
		for i := 0; i < len(s); i += size{
			j += size
			if j >= len(s) {
				j = len(s)-1
			}
			newStruct := NewUnitOption(s[i], s[j-1], s[j])
			uo = append(uo, newStruct)
		}
		_ = Serialize(uo)
	}
	return 1
}
