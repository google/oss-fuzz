/*
 * Copyright 2025 Google LLC
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

#include <stdint.h>
#include <stddef.h>

#include <protobuf-c/protobuf-c.h>
#include "t/test-full.pb-c.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /*
     * Test the core protobuf-c parsing by unpacking as TestMess.
     * This message type contains repeated fields of all types including
     * nested messages, which exercises all parsing code paths in
     * protobuf_c_message_unpack().
     */
    ProtobufCMessage *msg = protobuf_c_message_unpack(
        &foo__test_mess__descriptor, NULL, size, data);
    if (msg != NULL) {
        protobuf_c_message_free_unpacked(msg, NULL);
    }

    return 0;
}
