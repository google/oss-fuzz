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
	char *source_code = (char *)malloc(size+1);
	if (source_code == NULL){
		return 0;
	}
	memcpy(source_code, data, size);
	source_code[size] = '\0';
	
	gravity_delegate_t delegate = {.error_callback = report_error};    
    gravity_compiler_t *compiler = gravity_compiler_create(&delegate);
    gravity_closure_t *closure = gravity_compiler_run(compiler, source_code, strlen(source_code), 0, true, true);
	free(source_code);
	gravity_compiler_free(compiler);
    return 0;
}