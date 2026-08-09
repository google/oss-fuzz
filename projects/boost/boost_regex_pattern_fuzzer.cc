/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// The ideal place for this fuzz target is the boost repository.
#include <boost/regex.hpp>
#ifdef DEBUG
#include <iostream>
#endif
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);
    // Currently, we just consume all the fuzzed corpus into the regex pattern
    std::string regex_string = fdp.ConsumeRemainingBytesAsString();
    const uint8_t where_array[] = {0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48,0x48};
    std::string random(where_array, where_array + sizeof(where_array));
    std::string empty("");
    std::string spaces("                         ");
    try {
        std::vector<std::string> wheres;
        wheres.push_back(random);
        wheres.push_back(empty);
        wheres.push_back(spaces);
        boost::regex e(regex_string);
        // We're using multiple texts to be matched.
#ifdef DEBUG
        std::cout << "Regexp string: " << regex_string << "Size: " << regex_string.size() << std::endl;
#endif

        for (const auto& where : wheres) {
            try {
                boost::match_results<std::string::const_iterator> what;
                bool match = boost::regex_match(where, what, e, boost::match_default | boost::match_partial | boost::match_posix | boost::match_any);
            } catch(...) {
            }

            try {
                boost::match_results<std::string::const_iterator> what;
                bool match = boost::regex_match(where, what, e, boost::match_default | boost::match_partial | boost::match_perl | boost::match_any);
            } catch(...) {
            }
        }
    } catch(...) {
    }
    return 0;
}
