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

#include <stdarg.h>

#include "ntp.h"
#include "ntpd.h"
#include "ntp_calendar.h"
#include "ntp_leapsec.h"

#define kMinInputLength 4
#define kMaxInputLength 2048

int validate_check(uint8_t *Data);
int load_check(uint8_t *Data);

__attribute__((no_sanitize("address","memory","undefined"))) static int stringreader(void* farg)
{
	const char ** cpp = (const char**)farg;
	if (**cpp) {
		return *(*cpp)++;
	} else {
	    return EOF;
	}
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {//ntpsec/tests/ntpd/leapsec.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    validate_check((uint8_t *)Data);
    return load_check((uint8_t *)Data);
}

int validate_check(uint8_t *Data){
	int rc = leapsec_validate(stringreader, &Data);
    return rc;
}

int load_check(uint8_t *Data){
	bool    rc;
	leap_table_t * pt = leapsec_get_table(0);
	rc = (pt != NULL) && leapsec_load(pt, stringreader, &Data);
	rc = rc && leapsec_set_table(pt);
	return rc;
}
