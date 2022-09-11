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

package regexp

func FuzzCompile(data []byte) int {
	_, _ = Compile(string(data))
	return 1
}

func FuzzCompilePOSIX(data []byte) int {
	_, _ = CompilePOSIX(string(data))
	return 1
}

func FuzzReplaceAll(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	chunk1Len := int(data[0])
	chunk2Len := int(data[1])

	if chunk2Len <= chunk1Len || chunk1Len < 3 || len(data) < (chunk2Len+2) {
		return 0
	}

	chunk1 := data[2:chunk1Len]
	chunk2 := data[chunk1Len+1 : chunk2Len]
	chunk3 := data[chunk2Len+1:]

	re, err := Compile(string(chunk1))
	if err != nil {
		return 0
	}

	_ = re.ReplaceAll(chunk2, chunk3)
	return 1
}

func FuzzFindMatchApis(data []byte) int {
	if len(data) < 5 {
		return 0
	}
	callType := int(data[0])
	chunk1Len := int(data[1])

	data = data[2:]

	if chunk1Len+2 >= len(data) {
		return 0
	}

	reString := string(data[:chunk1Len])
	apiPayload := data[chunk1Len+1:]
	re, err := Compile(reString)
	if err != nil {
		return 0
	}

	switch callType % 6 {
	case 0:
		_ = re.FindIndex(apiPayload)
	case 1:
		_ = re.FindString(string(apiPayload))
	case 2:
		_ = re.FindStringIndex(string(apiPayload))
	case 3:
		_ = re.FindSubmatch(apiPayload)
	case 4:
		_ = re.MatchString(string(apiPayload))
	case 5:
		_ = re.Match(apiPayload)
	}
	return 1
}
