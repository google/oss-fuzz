package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestExtractMissingHeader(t *testing.T) {
	missingHeaderMessage := `path/to/file.cpp:8:10: fatal error: 'missingheader.h' file not found

	#include "missingheader.h"

		^~~~~~~~~~~~

	1 error generated.
	`

	res, _ := ExtractMissingHeader(missingHeaderMessage)
	expected := "missingheader.h"
	if strings.Compare(res, expected) != 0 {
		t.Errorf("Got: %s. Expected: %s.", res, expected)
	}
}

func TestGetHeaderCorrectedFilename(t *testing.T) {
	missingHeaderMessage := `path/to/file.cpp:8:10: fatal error: 'missingheader.h' file not found

	#include "missingheader.h"

		^~~~~~~~~~~~

	1 error generated.
	`
	_, correctedFilename, _ := GetHeaderCorrectedFilename(missingHeaderMessage)
	expected := "path/to/jcc-corrected-file.cpp"
	if strings.Compare(correctedFilename, expected) != 0 {
		t.Errorf("Got: %s. Expected: %s.", correctedFilename, expected)
	}
}

func TestFindMissingHeader(t *testing.T) {
	pwd, _ := os.Getwd()
	t.Setenv("JCC_MISSING_HEADER_SEARCH_PATH", pwd)

	location, _ := FindMissingHeader("header.h")
	expected := pwd + "/testdata/path/to/header.h"
	if strings.Compare(location, expected) != 0 {
		t.Errorf("Got: %s. Expected: %s.", location, expected)
	}
}

func TestCorrectMissingHeaders(t *testing.T) {
	pwd, _ := os.Getwd()
	t.Setenv("JCC_MISSING_HEADER_SEARCH_PATH", pwd)
	cfile := pwd + "/testdata/cfile.c"
	cmd := [4]string{"-fsanitize=address", cfile, "-o", "/tmp/blah"}
	res, err := CorrectMissingHeaders("clang", cmd[:])
	if !res {
		fmt.Println(err)
		t.Errorf("Expected successful compilation")
	}
}

func TestGetHeaderCorrectedCmd(t *testing.T) {
	compilerErr := `testdata/cpp.cc:8:10: fatal error: 'missingheader.h' file not found

	#include "missingheader.h"

		^~~~~~~~~~~~

	1 error generated.
	`

	cmd := [3]string{"-fsanitize=address", "file.cpp", "path/to/cpp.cc"}
	expectedFixedCmd := [3]string{"-fanitize=address", "file.cpp", "path/to/jcc-corrected-cpp.cc"}
	fixedCmd, _, _ := GetHeaderCorrectedCmd(cmd[:], compilerErr)
	if strings.Compare(fixedCmd[1], expectedFixedCmd[1]) != 0 {
		t.Errorf("Expected %s, got: %s", expectedFixedCmd, fixedCmd)
	}
}

func TestCppifyHeaderIncludes(t *testing.T) {
	t.Setenv("JCC_CPPIFY_PROJECT_HEADERS", "1")
	src := `// Copyright blah
#include <stddef.h>

#include "fuzz.h"
#include "x/y.h"
extern "C" LLVMFuzzerTestOneInput(uint8_t* data, size_t sz) {
  return 0;
}`
	newFile, _ := CppifyHeaderIncludes(src)
	expected := `// Copyright blah
#include <stddef.h>

extern "C" {
#include "fuzz.h"
}
extern "C" {
#include "x/y.h"
}
extern "C" LLVMFuzzerTestOneInput(uint8_t* data, size_t sz) {
  return 0;
}
/* JCCCppifyHeadersMagicString */
`
	if strings.Compare(newFile, expected) != 0 {
		t.Errorf("Expected: %s, got: %s", expected, newFile)
	}
}

func TestCppifyHeaderIncludesShouldnt(t *testing.T) {
	src := `// Copyright blah
#include <stddef.h>

#include "fuzz.h"
#include "x/y.h"
extern "C" LLVMFuzzerTestOneInput(uint8_t* data, size_t sz) {
  return 0;
}`
	newFile, _ := CppifyHeaderIncludes(src)
	if strings.Compare(newFile, src) != 0 {
		t.Errorf("Expected: %s. Got: %s", src, newFile)
	}
}

func TestCppifyHeaderIncludesAlready(t *testing.T) {
	src := `// Copyright blah
#include <stddef.h>

#include "fuzz.h"
#include "x/y.h"
extern "C" LLVMFuzzerTestOneInput(uint8_t* data, size_t sz) {
  return 0;
}
/* JCCCppifyHeadersMagicString */
`
	newFile, _ := CppifyHeaderIncludes(src)
	if strings.Compare(newFile, src) != 0 {
		t.Errorf("Expected %s, got: %s", src, newFile)
	}
}

func TestExtractMissingHeaderNonHeaderFailure(t *testing.T) {
	missingHeaderMessage := `clang: error: no such file or directory: 'x'
clang: error: no input files`

	header, res := ExtractMissingHeader(missingHeaderMessage)
	if res {
		t.Errorf("Expected no match, got: %s", header)
	}
}

func TestReplaceMissingHeader(t *testing.T) {
	cfile := `// Copyright 2035 Robots
#include <stddef.h>

#include <cstdint>

// Some libraries like OpenSSL will use brackets for their own headers.
#include <missingheader.h>

int LLVMFuzzerTestOneInput(uint8_t* data,  size_t size) {
  return 0;
}
`

	res := ReplaceMissingHeader(cfile, "missingheader.h", "path/to/includes/missingheader.h")
	expected := `// Copyright 2035 Robots
#include <stddef.h>

#include <cstdint>

// Some libraries like OpenSSL will use brackets for their own headers.
#include "path/to/includes/missingheader.h"

int LLVMFuzzerTestOneInput(uint8_t* data,  size_t size) {
  return 0;
}
`
	if strings.Compare(res, expected) != 0 {
		t.Errorf("Got: %s. Expected: %s.", res, expected)
	}
}
