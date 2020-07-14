#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

using std::string;
// #include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
// #include "uriparser_fuzzer.pb.h"
#include "uriparser/include/uriparser/Uri.h"
#include "uriparser/include/uriparser/UriBase.h"

class UriParserA {
 public:
  UriParserA() { memset((void *)&uri_, 0, sizeof(uri_)); }
  ~UriParserA() { uriFreeUriMembersA(&uri_); }

  UriUriA *get_mutable_uri() { return &uri_; }
  UriUriA *get_uri() const { return const_cast<UriUriA *>(&uri_); }

 private:
  UriUriA uri_;
};

void Escapes(const std::string &uri) {
  const char *first = uri.c_str();
  // A new line char takes 6 char to encode.
  // Use a vector to make a C string.
  std::vector<char> buf(uri.size() * 6 + 1);
  char *result = uriEscapeA(first, &buf[0], URI_TRUE, URI_TRUE);
  result = uriEscapeA(first, &buf[0], URI_FALSE, URI_FALSE);
}

void FileNames(const std::string &uri) {
  const size_t size = 8 + 3 * uri.size() + 1;
  std::vector<char> buf(size);
}

// Yuck!  The header situation for uriparse is rough.
extern "C" {
int uriParseIpFourAddressA(unsigned char *octetOutput, const char *first,
                           const char *afterLast);
}

void Ipv4(const std::string &s) {
  const char *cstr = s.c_str();
  unsigned char result[4] = {};
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  FuzzedDataProvider stream(data, size);

  bool domainrelative = stream.ConsumeBool();
  size_t uriSize = stream.remaining_bytes() / 2;

  const std::string uri1 = stream.ConsumeBytesAsString(uriSize);
  const std::string uri2 = stream.ConsumeBytesAsString(uriSize);

  Escapes(uri1);
  Escapes(uri2);

  FileNames(uri1);
  FileNames(uri2);

  Ipv4(uri1);
  Ipv4(uri2);

  UriParserA parser1;
  UriParserStateA state1;
  state1.uri = parser1.get_mutable_uri();
  if (URI_SUCCESS != uriParseUriA(&state1, uri1.c_str())) return 0;

  {
    char buf[1024 * 8] = {};
    int written = 0;
    uriToStringA(buf, state1.uri, sizeof(buf), &written);
  }

  UriParserA parser2;
  UriParserStateA state2;
  state2.uri = parser2.get_mutable_uri();
  if (URI_SUCCESS != uriParseUriA(&state2, uri2.c_str())) return 0;

  uriEqualsUriA(state1.uri, state2.uri);

  uriNormalizeSyntaxA(state1.uri);

  UriUriA absUri;
  uriAddBaseUriA(&absUri, state1.uri, state2.uri);
  uriFreeUriMembersA(&absUri);

  UriUriA relUri;
  uriRemoveBaseUriA(&relUri, state1.uri, state2.uri, domainrelative);
  uriFreeUriMembersA(&relUri);

  return 0;
}
