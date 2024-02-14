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

package influxdb

import (
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

func prepareReader(text string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(text))
}

func FuzzInfluxDBResponseParser(data []byte) int {
	parser := &ResponseParser{}
	query := &Query{}
	_ = parser.Parse(prepareReader(string(data)), query)
	return 1
}

func FuzzInfluxDBModelParser(data []byte) int {
	parser := &InfluxdbQueryParser{}
	query := backend.DataQuery{
		JSON:     []byte(data),
		Interval: time.Second * 10,
	}
	_, _ = parser.Parse(query)
	return 1
}
