#include <stdint.h>
#include <stdio.h>
#include <string>
#include "util/tc_common.h"
#include "util/tc_socket.h"
#include "util/tc_clientsocket.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        if(int(size)<3) {
                return 1;
        }
        std::string input(reinterpret_cast<const char*>(data), size);

        tars::TC_Endpoint t;
        t.parse(input);

        return 0;
}
