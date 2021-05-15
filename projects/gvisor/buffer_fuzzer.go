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

package buffer

import (
	"bytes"
	"context"
	"errors"
	"gvisor.dev/gvisor/pkg/state"
)


func doSaveAndLoad(toSave, toLoad *View) (err error) {
	var buf bytes.Buffer
	ctx := context.Background()
	if _, err := state.Save(ctx, &buf, toSave); err != nil {
		return errors.New("Save failed")
	}
	if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), toLoad); err != nil {
		return errors.New("Load failed")
	}
	return nil
}

func StateBufferFuzz(data []byte) int {
	var toSave View
	toSave.Append(data)

	var v View
	err := doSaveAndLoad(&toSave, &v)
	if err != nil {
		return 0
	}
	return 1
}
