/* Copyright 2021 Google LLC
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

#include "config.h"
#include "syshead.h"
#include "init.h"
#include "packet_id.h"

#include "fuzz_randomizer.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_random_init(data, size);

  struct packet_id pid;
  struct packet_id_net pin;
  const int seq_backtrack = 10;
  const int time_backtrack = 10;

  packet_id_init(&pid, seq_backtrack, time_backtrack, "name", 0);

  update_time();
  pin.time = fuzz_randomizer_get_int(0, 123123);
  pin.id = fuzz_randomizer_get_int(0, 123123);

  packet_id_reap_test(&pid.rec);
  bool test = packet_id_test(&pid.rec, &pin);
  if (test) {
    packet_id_add(&pid.rec, &pin);
  }
  packet_id_free(&pid);

	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

	FILE *fp = fopen(filename, "wb");
	if (!fp) {
    return 0;
	}
	fwrite(data, size, 1, fp);
	fclose(fp);
 
  struct packet_id_persist p;
  memset(&p, 0, sizeof(struct packet_id_persist));
  packet_id_persist_init(&p);
  packet_id_persist_load(&p, filename);
  packet_id_persist_close(&p); 

  fuzz_random_destroy();
  return 0;
}

