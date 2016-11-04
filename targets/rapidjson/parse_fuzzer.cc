// Based on rapidjson/example/simpledom/simpledom.cpp`
#include <iostream>
#include "rapidjson/document.h"
#include "rapidjson/memorystream.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  const char* s = reinterpret_cast<const char*>(Data);
  MemoryStream ms(s, Size);

  //  Parse a JSON string into DOM.
  Document d;
  d.ParseStream(ms);
  if (d.HasParseError()) {
    return 0;
  }

  //  Stringify the DOM
  StringBuffer buffer;
  Writer<StringBuffer> writer(buffer);
  d.Accept(writer);
  buffer.GetString();
  return 0;
}
