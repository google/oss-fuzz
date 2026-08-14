/* Copyright 2026 Google LLC
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

/*
 * Fuzz target for ostree RFC 2616 date/time parser.
 * Exercises _ostree_parse_rfc2616_date_time used for HTTP date headers.
 */

#include "config.h"
#include <glib.h>
#include <string.h>
#include <stdint.h>

#include "ostree-date-utils-private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1)
    return 0;

  /* The parser expects exactly 29 characters but let's test with
   * various lengths to exercise boundary conditions */
  g_autoptr(GDateTime) dt = _ostree_parse_rfc2616_date_time(
      (const char *)data, size);

  /* If parsed, exercise the resulting DateTime */
  if (dt)
    {
      g_date_time_get_year(dt);
      g_date_time_get_month(dt);
      g_date_time_get_day_of_month(dt);
      g_date_time_get_hour(dt);
      g_date_time_get_minute(dt);
      g_date_time_get_second(dt);
    }

  return 0;
}
