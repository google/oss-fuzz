// Copyright 2022 Google LLC
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

package unicode

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"golang.org/x/text/encoding/charmap"
)

var (
	utf16LEIB = UTF16(LittleEndian, IgnoreBOM) // UTF-16LE (atypical interpretation)
	utf16LEUB = UTF16(LittleEndian, UseBOM)    // UTF-16, LE
	utf16LEEB = UTF16(LittleEndian, ExpectBOM) // UTF-16, LE, Expect
	utf16BEIB = UTF16(BigEndian, IgnoreBOM)    // UTF-16BE (atypical interpretation)
	utf16BEUB = UTF16(BigEndian, UseBOM)       // UTF-16 default
	utf16BEEB = UTF16(BigEndian, ExpectBOM)    // UTF-16 Expect
)

func FuzzUnicodeTransform(data []byte) int {
	f := fuzz.NewConsumer(data)
	sizeDest, err := f.GetInt()
	if err != nil {
		return 0
	}
	b, err := f.GetBytes()
	if err != nil {
		return 0
	}

	b2 := make([]byte, sizeDest)

	decoderType, err := f.GetInt()
	if err != nil {
		return 0
	}
	boo, err := f.GetBool()
	if err != nil {
		return 0
	}

	switch decoderType % 10 {
	case 0:
		utf16LEIB.NewDecoder().Transform(b2, b, boo)
	case 1:
		utf16LEUB.NewDecoder().Transform(b2, b, boo)
	case 2:
		utf16LEEB.NewDecoder().Transform(b2, b, boo)
	case 3:
		utf16BEIB.NewDecoder().Transform(b2, b, boo)
	case 4:
		utf16BEUB.NewDecoder().Transform(b2, b, boo)
	case 5:
		utf16BEEB.NewDecoder().Transform(b2, b, boo)
	case 6:
		UTF8.NewDecoder().Transform(b2, b, boo)
	case 7:
		UTF8BOM.NewDecoder().Transform(b2, b, boo)
	case 8:
		tr := UTF8BOM.NewEncoder()
		tr.Reset()
		tr.Transform(b2, b, boo)
	case 9:
		tr := BOMOverride(charmap.CodePage437.NewDecoder())
		tr.Reset()
		tr.Transform(b2, b, boo)
	}

	return 1
}
