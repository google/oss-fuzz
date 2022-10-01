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

#include "gpsd_config.h"  /* must be before all includes */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gps.h"
#include "libgps.h"
#include "gpsdclient.h"

#define kMinInputLength 10
#define kMaxInputLength 8192

static struct gps_data_t gpsdata;

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//gpsd/tests//test_libgps.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    gps_unpack((char*)Data, &gpsdata);

    return 0;
}
