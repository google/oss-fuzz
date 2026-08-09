/*
 * Fuzzing of boost property tree parsers.
 * by Paul Dreik 20180818
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <boost/property_tree/xml_parser.hpp>
#include <sstream>

int
readXml(const char* Data, size_t Size)
{

  namespace pt = boost::property_tree;

  if (Size < 1) {
    // no data to use for flags - skip.
    return 0;
  }

  std::stringstream ss;
  const auto firstbyte = Data[0];

  ss.write(Data + 1, Size - 1);

  pt::ptree tree;

  try {
    // set the parse flags based on the first byte
    int flags = 0;
    if (firstbyte & 0x1) {
      flags |= pt::xml_parser::no_concat_text;
    }
    if (firstbyte & 0x2) {
      flags |= pt::xml_parser::no_comments;
    }
    if (firstbyte & 0x4) {
      flags |= pt::xml_parser::trim_whitespace;
    }
    pt::read_xml(ss, tree, flags);

    return tree.size() ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  readXml(reinterpret_cast<const char*>(Data), Size);
  return 0;
}
