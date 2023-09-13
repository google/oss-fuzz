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
