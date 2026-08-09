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
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/name_generator.hpp>
#include <boost/uuid/uuid_hash.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <fuzzer/FuzzedDataProvider.h>

using namespace std;
using namespace boost::uuids;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
    
    try{
        FuzzedDataProvider fdp(Data, Size);
        std::string s = fdp.ConsumeRemainingBytesAsString();

        string_generator gen_string;
        name_generator_sha1 gen_name(ns::url());
        hash<uuid> hasher;

        uuid u_string, u_name;

        u_string = gen_string(s);
        u_name = gen_name(s);
        
        size_t string_hash = hasher(u_string);
        size_t name_hash = hash_value(u_name);
        size_t uuid_hash_value = hasher(boost::uuids::uuid());

        string out_string = to_string(u_string);
        wstring out_wstring = to_wstring(u_string);

        swap(u_string, u_name);
    } catch(...) {
    }

    return 0;
}
