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
//

package xpkg

import (
	"bytes"
	"context"
	"io/ioutil"

	"github.com/crossplane/crossplane-runtime/pkg/parser"
	"k8s.io/apimachinery/pkg/runtime"
)

func FuzzParse(data []byte) int {
	objScheme := runtime.NewScheme()
	metaScheme := runtime.NewScheme()
	p := parser.New(metaScheme, objScheme)
	r := ioutil.NopCloser(bytes.NewReader(data))
	_, _ = p.Parse(context.TODO(), r)
	return 1
}
