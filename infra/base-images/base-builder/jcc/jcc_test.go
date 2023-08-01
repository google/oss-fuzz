package jcc

import (
	"strings"
	"testing"
)

func TestExtractMissingHeader(t *testing.T) {
	missingHeaderMessage := `path/to/file.cpp:8:10: fatal error: 'missingheader.h' file not found
#include "missingheader.h"
         ^~~~~~~~~~~~
1 error generated.
`
	res := ExtractMissingHeader(missingHeaderMessage)
	expected := "missingheader.h"
	if strings.Compare(res, expected) != 0 {
		t.Errorf("Got: %s. Expected: %s", res)
	}
}
