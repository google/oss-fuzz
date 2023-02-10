/*
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
*/
#include <stddef.h>
#include <stdint.h>

#include "dbus/message.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _c_cleanup_(message_unrefp) Message *message = NULL;
        MessageHeader *header = (void *)data;
        int r;

        if (size < sizeof(MessageHeader))
                return 0;

        r = message_new_incoming(&message, *header);
        if (r != 0)
                return 0;

        if (message->n_data > size)
                return 0;

        memcpy(message->data + sizeof(*header), data + sizeof(*header), message->n_data - sizeof(*header));

        r = message_parse_metadata(message);
        if (r)
                return 0;

        message_stitch_sender(message, 1);

        return 0;
}
