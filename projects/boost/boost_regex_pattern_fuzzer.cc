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
    
    // Consume a portion of data for regex pattern
    size_t pattern_size = fdp.ConsumeIntegralInRange<size_t>(0, Size);
    std::string regex_string = fdp.ConsumeBytesAsString(pattern_size);
    
    // Use remaining data to generate multiple test strings
    std::vector<std::string> wheres;
    while (fdp.remaining_bytes() > 0) {
        // Consume random length strings from remaining data
        size_t str_len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
        wheres.push_back(fdp.ConsumeBytesAsString(str_len));
        
        // Limit to reasonable number of test strings
        if (wheres.size() >= 10) {
            break;
        }
    }
    
    // Always include empty string as a test case
    if (wheres.empty() || std::find(wheres.begin(), wheres.end(), std::string("")) == wheres.end()) {
        wheres.push_back("");
    }
    
    try {
        boost::regex e(regex_string);
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