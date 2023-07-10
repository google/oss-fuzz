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

package policy

import (
	"github.com/go-logr/logr"
	kyverno "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/openapi"
	"testing"

	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
)

var fuzzOpenApiManager openapi.Manager

func init() {
	var err error
	fuzzOpenApiManager, err = openapi.NewManager(logr.Discard())
	if err != nil {
		panic(err)
	}
}

func FuzzValidatePolicy(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		p := &kyverno.ClusterPolicy{}
		ff.GenerateStruct(p)

		Validate(p, nil, nil, true, fuzzOpenApiManager, "admin")
	})
}
