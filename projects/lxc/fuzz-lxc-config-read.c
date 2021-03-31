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

#include <stddef.h>
#include <stdint.h>

#include "conf.h"
#include "confile.h"
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "fuzz-lxc-config-read-XXXXXX";
	struct lxc_conf *conf = NULL;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_write_nointr(fd, data, size);
	close(fd);

	conf = lxc_conf_init();
	lxc_config_read(tmpf, conf, false);
	lxc_conf_free(conf);

	(void) unlink(tmpf);
	return 0;
}
