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
#include <stdint.h>
#include "brpc/server.h"
#include "brpc/details/http_message.h"
#include "brpc/policy/http_rpc_protocol.h"
#include "echo.pb.h"

#define kMinInputLength 5
#define kMaxInputLength 1024

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*incubator-brpc/test/brpc_http_message_unittest.cpp*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    brpc::HttpMessage http_message;
    http_message.ParseFromArray((char *)Data, Size);

    return 0;
}
