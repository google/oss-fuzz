/*
# Copyright 2021 Google Inc.
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
#include "libbpf.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	struct bpf_object *obj = NULL;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	int err;

	libbpf_set_print(libbpf_print_fn);

	opts.object_name = "fuzz-object";
	obj = bpf_object__open_mem(data, size, &opts);
	err = libbpf_get_error(obj);
	if (err)
		return 0;

	bpf_object__close(obj);
	return 0;
}
