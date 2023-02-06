/* Copyright 2022 Google LLC
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

#include <iostream>
#include <cassert>
#include <string>

#include "EsiParser.h"
#include "Utils.h"

using std::string;
using namespace EsiLib;

#define kMinInputLength 5
#define kMaxInputLength 1024

void
Debug(const char *tag, const char *fmt, ...)
{
    return;
}

void
Error(const char *fmt, ...)
{
    return;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*trafficserver/plugins/esi/test/docnode_test.cc*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    Utils::init(&Debug, &Error);
    EsiParser parser("parser_test", &Debug, &Error);

    bool ret;
    DocNodeList node_list;
    string input_data((char *)Data,Size);

    ret = parser.completeParse(node_list, input_data);

    if(ret == true){
        DocNodeList node_list2;
        string packed = node_list.pack();
        node_list2.unpack(packed);
        node_list2.clear();
    }

    node_list.clear();

    return ret;
}
