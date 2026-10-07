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

#include <boost/property_tree/json_parser.hpp>
#include <sstream>

int
readJson(const char* Data, size_t Size)
{

  namespace pt = boost::property_tree;

  std::stringstream ss;
  ss.write(Data, Size);

  pt::ptree tree;

  try {
    pt::read_json(ss, tree);

    return tree.size() ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  readJson(reinterpret_cast<const char*>(Data), Size);
  return 0;
}
