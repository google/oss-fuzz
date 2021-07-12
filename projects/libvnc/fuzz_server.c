/*
# Copyright 2021 Google LLC
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
################################################################################
*/

#include <rfb/rfb.h>

static int initialized = 0;
rfbScreenInfoPtr server;
char *fakeargv[] = {"fuzz_server"};

extern size_t fuzz_offset;
extern size_t fuzz_size;
extern const uint8_t *fuzz_data;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (initialized == 0) {
        int fakeargc=1;
        server=rfbGetScreen(&fakeargc,fakeargv,400,300,8,3,4);
        server->frameBuffer=malloc(400*300*4);
        rfbInitServer(server);
        initialized = 1;
    }
    rfbClientPtr cl = rfbNewClient(server, RFB_INVALID_SOCKET - 1);

    fuzz_data = Data;
    fuzz_offset = 0;
    fuzz_size = Size;
    while (cl->sock != RFB_INVALID_SOCKET) {
        rfbProcessClientMessage(cl);
    }
    rfbClientConnectionGone(cl);
    return 0;
}
