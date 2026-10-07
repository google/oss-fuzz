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

package mock

import (
	"bytes"
	"compress/gzip"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/hyperledger/fabric/core/chaincode/persistence"
	tm "github.com/stretchr/testify/mock"
	"os"
)

func FuzzPersistence(data []byte) int {
	var ccpp persistence.ChaincodePackageParser
	mockMetaProvider := &MetadataProvider{}
	mockMetaProvider.On("GetDBArtifacts", tm.Anything).Return([]byte("DB artefacts"), nil)
	ccpp.MetadataProvider = mockMetaProvider
	_, _ = ccpp.Parse(data)
	return 1
}

func FuzzChaincodePackageStreamerMetadatabytes(data []byte) int {
	err := os.WriteFile("demoTar.tar", data, 0666)
	if err != nil {
		return 0
	}
	defer os.Remove("demoTar.tar")
	cps := &persistence.ChaincodePackageStreamer{PackagePath: "demoTar.tar"}
	_, _ = cps.MetadataBytes()
	return 1
}

func FuzzParseChaincodePackage(data []byte) int {
	f := fuzz.NewConsumer(data)
	source, err := f.TarBytes()
	if err != nil {
		return 0
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(source)
	w.Close()
	_, _, _ = persistence.ParseChaincodePackage(b.Bytes())
	return 1
}
