// Copyright 2020 Google LLC
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

package mypackagebeingfuzzed

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestFuzzCorpus(t *testing.T) {
	dir := os.Getenv("FUZZ_CORPUS_DIR")
	if dir == "" {
		t.Logf("No fuzzing corpus directory set")
		return
	}
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Logf("Not fuzzing corpus directory %s", err)
		return
	}
	filename := ""
	defer func() {
		if r := recover(); r != nil {
			t.Error("Fuzz panicked in "+filename, r)
		}
	}()
	for i := range infos {
		filename = dir + infos[i].Name()
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Error("Failed to read corpus file", err)
		}
		FuzzFunction(data)
	}
}
