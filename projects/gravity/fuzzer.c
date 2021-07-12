/* Copyright 2020 Google LLC
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "gravity_compiler.h"
#include "gravity_macros.h"
#include "gravity_core.h"
#include "gravity_vm.h"

static void report_error (gravity_vm *vm, error_type_t error_type,
						  const char *description, error_desc_t error_desc, void *xdata) {
	//printf("%s\n", description);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	gravity_delegate_t delegate = {.error_callback = report_error};    
	gravity_compiler_t *compiler = gravity_compiler_create(&delegate);
	gravity_closure_t *closure = gravity_compiler_run(compiler, data, size, 0, true, true);
	gravity_compiler_free(compiler);
	return 0;
}
