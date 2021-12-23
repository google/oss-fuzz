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

package normalizers

import (
	"encoding/json"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func UnstructuredForFuzzing(text string) (*unstructured.Unstructured, error) {
	un := &unstructured.Unstructured{}
	var err error
	if strings.HasPrefix(text, "{") {
		err = json.Unmarshal([]byte(text), &un)
	} else {
		err = yaml.Unmarshal([]byte(text), &un)
	}
	if err != nil {
		return nil, err
	}
	return un, nil
}

func FuzzNormalize(data []byte) int {
	f := fuzz.NewConsumer(data)
	ignore := make([]v1alpha1.ResourceIgnoreDifferences, 0)
	noOfIgnores, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfIgnores%30; i++ {
		ign := v1alpha1.ResourceIgnoreDifferences{}
		err = f.GenerateStruct(&ign)
		if err != nil {
			return 0
		}
		ignore = append(ignore, ign)
	}

	overrides := make(map[string]v1alpha1.ResourceOverride)
	err = f.FuzzMap(&overrides)
	if err != nil {
		return 0
	}

	unstructuredData, err := f.GetString()
	if err != nil {
		return 0
	}
	un, err := UnstructuredForFuzzing(unstructuredData)
	if err != nil {
		return 0
	}
	normalizer, err := NewIgnoreNormalizer(ignore, overrides)
	if err != nil {
		return 0
	}
	_ = normalizer.Normalize(un)
	return 1
}
