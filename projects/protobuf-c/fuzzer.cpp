/* Copyright 2025 Google LLC
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

/* Special thanks to Guido Vranken <guidovranken@gmail.com> */

#include <assert.h>
#include <stdlib.h>
#include <fuzzing/memory.hpp>
#include "test-full.pb-c.h"

#define X(OBJ, PREFIX) \
    { \
        OBJ* msg = PREFIX##__unpack(NULL, size, data); \
        if ( msg != NULL ) { \
            const size_t len = PREFIX##__get_packed_size(msg); \
            uint8_t* copy = (uint8_t*)malloc(len); \
            PREFIX##__pack(msg, copy); \
            fuzzing::memory::memory_test(copy, len); \
            free(copy); \
        } \
        PREFIX##__free_unpacked(msg, NULL); \
    }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    X(Foo__TestMessSubMess, foo__test_mess_sub_mess);
    X(Foo__TestFieldFlags, foo__test_field_flags);
    X(Foo__TestMessageCheck, foo__test_message_check);
    return 0;
}
