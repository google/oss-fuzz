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
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    try {
        boost::filesystem::path p(fdp.ConsumeRandomLengthString(5));

        p.replace_filename(fdp.ConsumeRandomLengthString(5));
        
        p.has_extension();
        p.extension();
        p.replace_extension(fdp.ConsumeRandomLengthString(3));
        
        boost::filesystem::path p1(fdp.ConsumeRandomLengthString(5));
        p.concat(p1);
        p.append(p1);
        p.remove_filename_and_trailing_separators();
        p /= (p1);
        p += (p1);
        
        p.lexically_relative(p1);
        p.filename_is_dot();
        p.remove_filename();
        
        p.swap(p1);
        p.root_directory();
        p.relative_path();
        p.parent_path();
        p.has_stem();
    } catch(...) {
    }
    return 0;
}