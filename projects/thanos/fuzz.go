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

package query

import (
	"fmt"
	"os"
	"time"
	"github.com/go-kit/kit/log"
	"github.com/thanos-io/thanos/pkg/store"
	"github.com/thanos-io/thanos/pkg/store/storepb"
	"github.com/prometheus/prometheus/storage"
	"github.com/thanos-io/thanos/pkg/component"
	"testing"
)

func init() {
	testing.Init()
}

func Fuzz(data []byte) int {
	t := &testing.T{}
	logger := log.NewLogfmtLogger(os.Stderr)
	var clients []store.Client
	q := NewQueryableCreator(
		logger,
		nil,
		store.NewProxyStore(logger, nil, func() []store.Client { return clients },
			component.Debug, nil, 5*time.Minute),
		1000000,
		5*time.Minute,
	)

	createQueryableFn := func(stores []*testStore) storage.Queryable {
		clients = clients[:0]
		for i, st := range stores {
			m, err := storepb.PromMatchersToMatchers(st.matchers...)
			if err != nil {
				panic("failure")
			}
			clients = append(clients, inProcessClient{
				t:           t,
				StoreClient: storepb.ServerAsClient(SelectedStore(store.NewTSDBStore(logger, st.storage.DB, component.Debug, nil), m, st.mint, st.maxt), 0),
				name:        fmt.Sprintf("store number %v", i),
			})
		}
		return q(true, nil, nil, 0, false, false)
	}

	te, err := newTest(t, string(data))
	if err != nil {
		return 0
	}
	te.run(createQueryableFn)
	te.close()
	return 1
}


