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

package oci

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func FuzzAppendDevicePermissionsFromCgroupRules(data []byte) int {
	f := fuzz.NewConsumer(data)
	sp := make([]specs.LinuxDeviceCgroup, 0)
	noOfRecords, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfRecords%40; i++ {
		s := specs.LinuxDeviceCgroup{}
		err := f.GenerateStruct(&s)
		if err != nil {
			return 0
		}
		sp = append(sp, s)
	}
	rules := make([]string, 0)
	f.CreateSlice(&rules)
	_, _ = AppendDevicePermissionsFromCgroupRules(sp, rules)
	return 1
}
