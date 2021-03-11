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

package user

import (
	"strings"
	"io"
)


func IsDivisbleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func Fuzz(data []byte) int {
	if len(data)==0 {
		return -1
	}
	divisible := IsDivisbleBy(len(data), 5)
	if divisible==false {
		return -1
	}

	var divided [][]byte

	chunkSize := len(data)/5

	for i := 0; i < len(data); i += chunkSize {
	    end := i + chunkSize

	    divided = append(divided, data[i:end])
	}

	_, _ = ParsePasswdFilter(strings.NewReader(string(divided[0])), nil)

	var passwd, group io.Reader

	group = strings.NewReader(string(divided[1]))
	_, _ = GetAdditionalGroups([]string{string(divided[2])}, group)


	passwd = strings.NewReader(string(divided[3]))
	_, _ = GetExecUser(string(divided[4]), nil, passwd, group)
	return 1
}
