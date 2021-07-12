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

package casext

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"github.com/opencontainers/umoci/oci/cas/dir"
)


func Fuzz(data []byte) int {
	ctx := context.Background()
	root, err := ioutil.TempDir("", "umoci-TestEngineBlobJSON")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(root)

	image := filepath.Join(root, "image")
	if err := dir.Create(image); err != nil {
		return -1
	}

	engine, err := dir.Open(image)
	if err != nil {
		return -1
	}
	engineExt := NewEngine(engine)
	defer engine.Close()

	digest, _, err := engineExt.PutBlobJSON(ctx, string(data))
	if err != nil {
		return 0
	}
	blobReader, err := engine.GetBlob(ctx, digest)
	if err != nil {
		return 0
	}
	defer blobReader.Close()

	_, err = ioutil.ReadAll(blobReader)
	if err != nil {
		return 0
	}
	return 1
}
