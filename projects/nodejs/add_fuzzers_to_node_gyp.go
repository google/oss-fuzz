// Copyright 2025 Google LLC
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

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	template1 = `
		{
		  'target_name': '____TARGETNAME____',
		  'type': 'executable',
		  'dependencies': [
		    '<(node_lib_target_name)',
		    'deps/googletest/googletest.gyp:gtest_prod',
		    'deps/histogram/histogram.gyp:histogram',
		    'deps/uvwasi/uvwasi.gyp:uvwasi',
		    'deps/ncrypto/ncrypto.gyp:ncrypto',
		    'deps/nbytes/nbytes.gyp:nbytes',
		    'tools/v8_gypfiles/abseil.gyp:abseil',
		  ],
		  'includes': [
		    'node.gypi'
		  ],
		  'include_dirs': [
		    'src',
		    'tools/msvs/genfiles',
		    'deps/v8/include',
		    'deps/cares/include',
		    'deps/uv/include',
		    'deps/uvwasi/include',
		    'test/cctest',
		    'test/fuzzers',
		  ],
		  'defines': [
		    'NODE_ARCH="<(target_arch)"',
		    'NODE_PLATFORM="<(OS)"',
		    'NODE_WANT_INTERNALS=1',
		    'HAVE_OPENSSL=1',
		    'NAPI_VERSION=10',
		  ],
		  'sources': [
		    'src/node_snapshot_stub.cc',
		    'test/fuzzers/fuzz_common.cc',
		    'test/fuzzers/____TARGETNAME____.cc',
		  ],
		  'conditions': [
		    ['OS=="linux"', {
		      'ldflags': [ '-fsanitize=fuzzer' ]
		    }],
		    # Ensure that ossfuzz flag has been set and that we are on Linux
		    [ 'OS!="linux" or ossfuzz!="true"', {
		      'type': 'none',
		    }],
		    # Avoid excessive LTO
		    ['enable_lto=="true"', {
		      'ldflags': [ '-fno-lto' ],
		    }],
		  ],
		},`
	fuzzers = []string{
		"fuzz_ClientHelloParser",
		"fuzz_blob",
		"fuzz_buffer_compare",
		"fuzz_buffer_equals",
		"fuzz_buffer_includes",
		"fuzz_cipheriv",
		"fuzz_createPrivateKeyDER",
		"fuzz_createPrivateKeyJWK",
		"fuzz_createPrivateKeyPEM",
		"fuzz_diffieHellmanDER",
		"fuzz_diffieHellmanJWK",
		"fuzz_diffieHellmanPEM",
		"fuzz_fs_write_open_read",
		"fuzz_fs_write_read_append",
		"fuzz_httpparser1",
		"fuzz_path_basename",
		"fuzz_path_dirname",
		"fuzz_path_extname",
		"fuzz_path_format",
		"fuzz_path_isAbsolute",
		"fuzz_path_join",
		"fuzz_path_normalize",
		"fuzz_path_parse",
		"fuzz_path_relative",
		"fuzz_path_resolve",
		"fuzz_path_toNamespacedPath",
		"fuzz_querystring_parse",
		"fuzz_quic_token",
		"fuzz_sign_verify",
		"fuzz_stream1",
		"fuzz_string_decoder",
		"fuzz_strings",
		"fuzz_tls_socket_request",
		"fuzz_v8_deserialize",
		"fuzz_x509",
		"fuzz_zlib_brotliCompress",
		"fuzz_zlib_brotliDecompress",
		"fuzz_zlib_createBrotliDecompress",
		"fuzz_zlib_gzip_createUnzip",
	}
)

func createGypTargetEntry(fuzzerName string) string {
	templ := template1
	templWithTargetName := strings.ReplaceAll(templ, "____TARGETNAME____", fuzzerName)
	return templWithTargetName
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <inputfile> <outputfile>")
		return
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	in, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open input file: %v", err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer out.Close()

	scanner := bufio.NewScanner(in)
	writer := bufio.NewWriter(out)

	var ignore bool

	for scanner.Scan() {
		line := scanner.Text()

		// Remove existing fuzzers in the original node.gyp
		if !ignore && line == "    { # fuzz_env" {
			ignore = true
			continue
		} else if ignore && line == "    }, # fuzz_env" {
			ignore = false
			continue
		} else if !ignore && line == "    { # fuzz_ClientHelloParser.cc" {
			ignore = true
			continue
		} else if ignore && line == "    }, # fuzz_ClientHelloParser.cc" {
			ignore = false
			continue
		} else if !ignore && line == "    { # fuzz_url" {
			ignore = true
			continue
		} else if ignore && line == "    }, # fuzz_url" {
			ignore = false
			continue
		} else if !ignore && line == "    { # fuzz_strings" {
			ignore = true
			continue
		} else if ignore && line == "    }, # fuzz_strings" {
			ignore = false
			continue
		}
		if ignore {
			continue
		}

		var stringToAppend string
		appendTargetsNow := line == "  'targets': ["
		// add new line unless we are adding the fuzzers
		// since the fuzzer template already has new line
		if appendTargetsNow {
			stringToAppend = line
		} else {
			stringToAppend = line + "\n"
		}
		_, err := writer.WriteString(stringToAppend)
		if err != nil {
			log.Fatalf("Failed to write line: %v", err)
		}

		// Check for the special line
		if appendTargetsNow {
			for _, fuzzer := range fuzzers {
				fmt.Println("appending ", fuzzer)
				_, err := writer.WriteString(createGypTargetEntry(fuzzer))
				if err != nil {
					log.Fatalf("Failed to write injected line: %v", err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input file: %v", err)
	}

	if err := writer.Flush(); err != nil {
		log.Fatalf("Error flushing output: %v", err)
	}
}
