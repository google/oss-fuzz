// Copyright 2022 Google LLC. All Rights Reserved.
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

package etchosts

import (
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzAdd(data []byte) int {
	f := fuzz.NewConsumer(data)
	fileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	noOfRecords, err := f.GetInt()
	if err != nil {
		return 0
	}

	recs := make([]Record, 0)
	for i := 0; i < noOfRecords%40; i++ {
		r := Record{}
		err = f.GenerateStruct(&r)
		if err != nil {
			return 0
		}
		recs = append(recs, r)
	}
	defer os.Remove("testFile")
	err = os.WriteFile("testFile", fileBytes, 0644)
	if err != nil {
		return 0
	}
	Add("testFile", recs)
	return 1
}
