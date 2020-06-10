#include <string> 

#include "absl/strings/escaping.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	std::string str (reinterpret_cast<const char*>(data), size);
	std::string escaped, unescaped;
	escaped = absl::CHexEscape(str);
	absl::CUnescape(escaped, &unescaped);
	
	escaped = absl::CEscape(str);
	absl::CUnescape(escaped, &unescaped);
	
	escaped = absl::Utf8SafeCEscape(str);
	absl::CUnescape(escaped, &unescaped);
	
	escaped = absl::Utf8SafeCHexEscape(str);
	absl::CUnescape(escaped, &unescaped);
	
	std::string encoded, decoded;
	absl::Base64Escape(str, &encoded);
	absl::Base64Unescape(encoded, &decoded);

	absl::WebSafeBase64Escape(str, &encoded);
	absl::WebSafeBase64Unescape(encoded, &decoded);

	std::string hex_result, bytes_result;
	hex_result = absl::BytesToHexString(str);
	bytes_result = absl::HexStringToBytes(hex_result);

	return 0;
}