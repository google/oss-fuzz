// Copyright 2023 Google LLC
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

package trustmanager

import (
	"bytes"
	"encoding/pem"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var initter sync.Once

func muteLogging() {
	logrus.SetLevel(logrus.PanicLevel)
}

func FuzzImportKeysSimple(f *testing.F) {
	f.Fuzz(func(t *testing.T, from []byte, fallbackRole, fallbackGUN string) {
		initter.Do(muteLogging)
		s := NewTestImportStore()

		in := bytes.NewReader(from)
		ImportKeys(in, []Importer{s}, fallbackRole, fallbackGUN, passphraseRetriever)
	})
}

func FuzzImportKeysStructured(f *testing.F) {
	f.Fuzz(func(t *testing.T, from, fuzzData []byte) {
		initter.Do(muteLogging)

		ff := fuzz.NewConsumer(fuzzData)

		b := &pem.Block{}
		headerMap1 := make(map[string]string)
		ff.FuzzMap(&headerMap1)
		b.Headers = headerMap1
		b.Bytes = from

		c := &pem.Block{}
		headerMap2 := make(map[string]string)
		ff.FuzzMap(&headerMap2)
		c.Bytes = from
		c.Headers = headerMap2

		bBytes := pem.EncodeToMemory(b)
		cBytes := pem.EncodeToMemory(c)

		byt := append(bBytes, cBytes...)

		in := bytes.NewBuffer(byt)

		s := NewTestImportStore()
		ImportKeys(in, []Importer{s}, "", "", passphraseRetriever)
	})
}
