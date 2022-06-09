// Copyright 2020 Google LLC
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

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

using std::string;
#include "uriparser/include/uriparser/Uri.h"
#include "uriparser/include/uriparser/UriIp4.h"

class UriParserA {
 public:
  UriParserA() { memset((void *)&uri_, 0, sizeof(uri_)); }
  ~UriParserA() { uriFreeUriMembersA(&uri_); }

  UriUriA *get_mutable_uri() { return &uri_; }
  UriUriA *get_uri() const { return const_cast<UriUriA *>(&uri_); }

 private:
  UriUriA uri_;
};

void Escapes(const string &uri) {
  const char *first = uri.c_str();
  // A new line char takes 6 char to encode.
  // Use a vector to make a C string.
  std::vector<char> buf1(uri.size() * 6 + 1);
  std::vector<char> buf2(uri.size() * 3 + 1);

  char *result;
  result = uriEscapeA(first, &buf1[0], URI_TRUE, URI_TRUE);
  result = uriEscapeA(first, &buf1[0], URI_FALSE, URI_TRUE);
  if (buf1.data()) uriUnescapeInPlaceA(&buf1[0]);

  result = uriEscapeA(first, &buf2[0], URI_TRUE, URI_FALSE);
  result = uriEscapeA(first, &buf2[0], URI_FALSE, URI_FALSE);
  if (buf2.data()) uriUnescapeInPlaceA(&buf2[0]);
}

void FileNames(const string &uri) {
  const size_t size = 8 + 3 * uri.size() + 1;
  std::vector<char> buf(size);

  uriUnixFilenameToUriStringA(uri.c_str(), &buf[0]);
  uriWindowsFilenameToUriStringA(uri.c_str(), &buf[0]);
  uriUriStringToUnixFilenameA(uri.c_str(), &buf[0]);
  uriUriStringToWindowsFilenameA(uri.c_str(), &buf[0]);
}

int uriParseIpFourAddressA(unsigned char *octetOutput, const char *first,
                           const char *afterLast);

void Ipv4(const string &s) {
  const char *cstr = s.c_str();
  unsigned char result[4] = {};
  uriParseIpFourAddressA(result, cstr, &cstr[s.size()]);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider stream(data, size);
  bool domainRelative = stream.ConsumeBool();
  size_t uriSize = stream.remaining_bytes() / 2;

  const string uri1 = stream.ConsumeBytesAsString(uriSize);
  const string uri2 = stream.ConsumeRemainingBytesAsString();

  Escapes(uri1);
  Escapes(uri2);

  FileNames(uri1);
  FileNames(uri2);

  Ipv4(uri1);
  Ipv4(uri2);

  UriParserA parser1;
  UriParserStateA state1;
  state1.uri = parser1.get_mutable_uri();
  if (uriParseUriA(&state1, uri1.c_str()) != URI_SUCCESS)
    return 0;

  char buf[1024 * 8] = {0};
  int written = 0;
  uriToStringA(buf, state1.uri, sizeof(buf), &written);

  UriParserA parser2;
  UriParserStateA state2;
  state2.uri = parser2.get_mutable_uri();
  if (uriParseUriA(&state2, uri2.c_str()) != URI_SUCCESS)
    return 0;

  uriEqualsUriA(state1.uri, state2.uri);

  uriNormalizeSyntaxA(state1.uri);

  UriUriA absUri;
  uriAddBaseUriA(&absUri, state1.uri, state2.uri);
  uriFreeUriMembersA(&absUri);

  UriUriA relUri;
  uriRemoveBaseUriA(&relUri, state1.uri, state2.uri, domainRelative);
  uriFreeUriMembersA(&relUri);

  return 0;
}
