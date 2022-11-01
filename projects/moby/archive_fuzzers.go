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

package archive

import (
	"bytes"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

func FuzzDecompressStream(data []byte) int {
	r := bytes.NewReader(data)
	_, _ = DecompressStream(r)
	return 1
}

func FuzzUntar(data []byte) int {
	f := fuzz.NewConsumer(data)
	tarBytes, err := f.TarBytes()
	if err != nil {
		return 0
	}
	options := &TarOptions{}
	err = f.GenerateStruct(options)
	if err != nil {
		return 0
	}
	defer os.Remove("testdir")
	err = os.Mkdir("testdir", 0750)
	if err != nil && !os.IsExist(err) {
		return 0
	}
	Untar(bytes.NewReader(tarBytes), "testdir", options)
	return 1
}

func FuzzApplyLayer(data []byte) int {
	defer os.Remove("testDir")
	err := os.Mkdir("testDir", 0750)
	if err != nil {
		return 0
	}
	_, _ = ApplyLayer("testDir", bytes.NewReader(data))
	return 1
}
