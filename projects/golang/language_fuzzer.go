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

package fuzztext

import (
	"golang.org/x/text/currency"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/cldr"
)

func FuzzMultipleParsers(data []byte) int {
	if len(data) < 2 {
		return 0
	}
	parser_type := int(data[0])
	data = data[1:]

	switch parser_type % 7 {
	case 0:
		_, _ = language.ParseExtension(string(data))
	case 1:
		_, _ = language.ParseBase(string(data))
	case 2:
		_, _ = language.ParseScript(string(data))
	case 3:
		_, _ = language.ParseRegion(string(data))
	case 4:
		_, _ = language.ParseVariant(string(data))
	case 5:
		_, _ = cldr.ParseDraft(string(data))
	case 6:
		_, _ = currency.ParseISO(string(data))
	}
	return 1
}
