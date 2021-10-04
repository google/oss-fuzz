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

package wal

import (
	"bytes"
	"io/ioutil"
	"os"

	"go.etcd.io/etcd/raft/v3/raftpb"
	"go.etcd.io/etcd/server/v3/storage/wal/walpb"
	"go.uber.org/zap"
)

func FuzzWalCreate(data []byte) int {
	p, err := ioutil.TempDir("/tmp", "waltest")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(p)
	w, err := Create(zap.NewExample(), p, data)
	if err != nil {
		return 0
	}
	if err = w.SaveSnapshot(walpb.Snapshot{}); err != nil {
		return 0
	}
	if err = w.Save(raftpb.HardState{}, []raftpb.Entry{{Index: 0}}); err != nil {
		return 0
	}
	w.Close()
	neww, err := Open(zap.NewExample(), p, walpb.Snapshot{})
	if err != nil {
		return 0
	}
	defer neww.Close()
	metadata, _, _, err := neww.ReadAll()
	if err != nil {
		return 0
	}
	if !bytes.Equal(data, metadata) {
		panic("data and metadata are not equal, but they should be")
	}
	return 1
}
