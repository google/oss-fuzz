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

package csv

import (
	"bytes"
	"github.com/minio/minio/internal/s3select/sql"
	"io/ioutil"
	"strings"
	"testing"
)

func FuzzTestRead(f *testing.F) {
	f.Add("1,2,3\na,b,c\n", "\n", ",")
	f.Add("1,2,3\ta,b,c\t", "\t", ",")
	f.Add("1,2,3\r\na,b,c\r\n", "\r\n", ",")
	f.Fuzz(func(t *testing.T, data1 string, data2 string, data3 string) {
		var err error
		var record sql.Record
		var result bytes.Buffer

		r, _ := NewReader(ioutil.NopCloser(strings.NewReader(data1)), &ReaderArgs{
			FileHeaderInfo:             none,
			RecordDelimiter:            data2,
			FieldDelimiter:             data3,
			QuoteCharacter:             defaultQuoteCharacter,
			QuoteEscapeCharacter:       defaultQuoteEscapeCharacter,
			CommentCharacter:           defaultCommentCharacter,
			AllowQuotedRecordDelimiter: false,
			unmarshaled:                true,
		})

		for {
			record, err = r.Read(record)
			if err != nil {
				break
			}
			opts := sql.WriteCSVOpts{
				FieldDelimiter: []rune(data3)[0],
				Quote:          '"',
				QuoteEscape:    '"',
				AlwaysQuote:    false,
			}
			record.WriteCSV(&result, opts)
			result.Truncate(result.Len() - 1)
			result.WriteString(data2)
		}
		r.Close()

	})
}
