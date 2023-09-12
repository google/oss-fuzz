package gin

import (
	"net/http"
)
import (
	"net/http/httptest"
)
import (
	"testing"
)

func FuzzTestContextNegotiationFormatWithAccept(f *testing.F) {
	f.Add(MIMEJSON, MIMEXML, MIMEHTML)
	f.Fuzz(func(t *testing.T, data1 string, data2 string, data3 string) {
		c, _ := CreateTestContext(httptest.NewRecorder())
		c.Request, _ = http.NewRequest("POST", "/", nil)
		c.Request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8")
		c.NegotiateFormat(data1, data2)
		c.NegotiateFormat(data2, data3)
		c.NegotiateFormat(data1)
	})
}
