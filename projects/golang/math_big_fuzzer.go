// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package mathfuzzer

import (
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"math"
	"math/big"
	"strconv"
	"strings"
)

func FuzzBigIntCmp1(data []byte) int {
	if !isDivisibleBy(len(data), 2) {
		return -1
	}
	i1 := new(big.Int)
	i2 := new(big.Int)

	half := len(data) / 2

	halfOne := data[:half]
	halfTwo := data[half:]

	i1.SetBytes(halfOne)
	i2.SetBytes(halfTwo)

	i1.Cmp(i2)
	return 1
}

func FuzzBigIntCmp2(data []byte) int {
	if !isDivisibleBy(len(data), 2) {
		return -1
	}
	x, y := new(big.Int), new(big.Int)
	half := len(data) / 2
	if err := x.UnmarshalText(data[:half]); err != nil {
		return 0
	}
	if err := y.UnmarshalText(data[half:]); err != nil {
		return 0
	}
	x.Cmp(y)
	return 1
}

func FuzzRatSetString(data []byte) int {
	_, _ = new(big.Rat).SetString(string(data))
	return 1
}

func FuzzFloatSetString(data []byte) int {
	f := fuzz.NewConsumer(data)
	f64, err := f.GetFloat64()
	if err != nil {
		return 0
	}
	if math.IsNaN(f64) {
		return 0
	}
	s, err := f.GetString()
	if err != nil {
		return 0
	}
	fl := big.NewFloat(f64)
	fl.SetString(s)
	return 1
}

func FuzzBigGobdecode(data []byte) int {
	f := fuzz.NewConsumer(data)
	buf, err := f.GetBytes()
	if err != nil {
		return 0
	}
	target, err := f.GetInt()
	if err != nil {
		return 0
	}
	switch target % 2 {
	case 0:
		i, err := f.GetInt()
		if err != nil {
			return 0
		}
		bi := big.NewInt(int64(i))
		bi.GobDecode(buf)
	case 1:
		i1, err := f.GetInt()
		if err != nil {
			return 0
		}
		i2, err := f.GetInt()
		if err != nil {
			return 0
		}
		if int64(i2) == 0 {
			return 0
		}
		r := big.NewRat(int64(i1), int64(i2))
		r.GobDecode(buf)
	}
	return 1
}

func isDivisibleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func FuzzFloat64SpecialCases(data []byte) int {
	input := string(data)
	if strings.HasPrefix(input, "long:") {
		input = input[len("long:"):]
	}

	r, ok := new(big.Rat).SetString(input)
	if !ok {
		return 0
	}
	f, exact := r.Float64()

	// 1. Check string -> Rat -> float64 conversions are
	// consistent with strconv.ParseFloat.
	// Skip this check if the input uses "a/b" rational syntax.
	if !strings.Contains(input, "/") {
		e, _ := strconv.ParseFloat(input, 64)

		// Careful: negative Rats too small for
		// float64 become -0, but Rat obviously cannot
		// preserve the sign from SetString("-0").
		switch {
		case math.Float64bits(e) == math.Float64bits(f):
			// Ok: bitwise equal.
		case f == 0 && r.Num().BitLen() == 0:
			// Ok: Rat(0) is equivalent to both +/- float64(0).
		default:
			return 0
			panic(fmt.Sprintf("strconv.ParseFloat(%q) = %g (%b), want %g (%b); delta = %g\n", input, e, e, f, f, f-e))
		}
	}

	if !isFiniteFuzz(f) {
		return 0
	}

	// 2. Check f is best approximation to r.
	if !checkIsBestApprox64Fuzz(f, r) {
		// Append context information.
		panic(fmt.Sprintf("(input was %q\n)", input))
	}

	// 3. Check f->R->f roundtrip is non-lossy.
	checkNonLossyRoundtrip64Fuzz(f)

	// 4. Check exactness using slow algorithm.
	if wasExact := new(big.Rat).SetFloat64(f).Cmp(r) == 0; wasExact != exact {
		fmt.Println(input)
		panic(fmt.Sprintf("Rat.SetString(%q).Float64().exact = %t, want %t\n", input, exact, wasExact))
	}
	return 1
}

func checkNonLossyRoundtrip64Fuzz(f float64) {
	if !isFiniteFuzz(f) {
		return
	}
	r := new(big.Rat).SetFloat64(f)
	if r == nil {
		panic(fmt.Sprintf("Rat.SetFloat64(%g (%b)) == nil\n", f, f))
	}
	f2, exact := r.Float64()
	if f != f2 || !exact {
		panic(fmt.Sprintf("Rat.SetFloat64(%g).Float64() = %g (%b), %v, want %g (%b), %v; delta = %b\n",
			f, f2, f2, exact, f, f, true, f2-f))
	}
}

func isFiniteFuzz(f float64) bool {
	return math.Abs(f) <= math.MaxFloat64
}

func checkIsBestApprox64Fuzz(f float64, r *big.Rat) bool {
	if math.Abs(f) >= math.MaxFloat64 {
		// Cannot check +Inf, -Inf, nor the float next to them (MaxFloat64).
		// But we have tests for these special cases.
		return true
	}

	// r must be strictly between f0 and f1, the floats bracketing f.
	f0 := math.Nextafter(f, math.Inf(-1))
	f1 := math.Nextafter(f, math.Inf(+1))

	// For f to be correct, r must be closer to f than to f0 or f1.
	df := deltaFuzz(r, f)
	df0 := deltaFuzz(r, f0)
	df1 := deltaFuzz(r, f1)
	if df.Cmp(df0) > 0 {
		panic(fmt.Sprintf("Rat(%v).Float64() = %g (%b), but previous float64 %g (%b) is closer", r, f, f, f0, f0))
	}
	if df.Cmp(df1) > 0 {
		panic(fmt.Sprintf("Rat(%v).Float64() = %g (%b), but next float64 %g (%b) is closer", r, f, f, f1, f1))
	}
	if df.Cmp(df0) == 0 && !isEven64Fuzz(f) {
		panic(fmt.Sprintf("Rat(%v).Float64() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f0, f0))
	}
	if df.Cmp(df1) == 0 && !isEven64Fuzz(f) {
		panic(fmt.Sprintf("Rat(%v).Float64() = %g (%b); halfway should have rounded to %g (%b) instead", r, f, f, f1, f1))
	}
	return true
}

func deltaFuzz(r *big.Rat, f float64) *big.Rat {
	d := new(big.Rat).Sub(r, new(big.Rat).SetFloat64(f))
	return d.Abs(d)
}

func isEven64Fuzz(f float64) bool { return math.Float64bits(f)&1 == 0 }
