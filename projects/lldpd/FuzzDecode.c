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
#include <stdlib.h>
#include <unistd.h>
#include "../src/daemon/lldpd.h"

#define kMinInputLength 30
#define kMaxInputLength 1500

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    int ret = 0;
    struct lldpd cfg;
	cfg.g_config.c_mgmt_pattern = NULL;

/* For decoding, we only need a very basic hardware */
	struct lldpd_hardware hardware;
	memset(&hardware, 0, sizeof(struct lldpd_hardware));
	hardware.h_mtu = 1500;
	strlcpy(hardware.h_ifname, "test", sizeof(hardware.h_ifname));

	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;

//Decoding
    ret += lldp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += cdp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += sonmp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);
    ret += edp_decode(&cfg, (char *)Data, Size, &hardware, &nchassis, &nport);

    return ret;
}
