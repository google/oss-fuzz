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

import "math/big"

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
    half := len(data)/2
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

func isDivisibleBy(n int, divisibleby int) bool {
    return (n % divisibleby) == 0
}
