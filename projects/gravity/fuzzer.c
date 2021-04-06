#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "gravity_compiler.h"
#include "gravity_macros.h"
#include "gravity_core.h"
#include "gravity_vm.h"

#define SOURCE	"func main() {var a = 10; var b=20; return a + b}"

static void report_error (gravity_vm *vm, error_type_t error_type,
                          const char *description, error_desc_t error_desc, void *xdata) {
    //printf("%s\n", description);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
		return 0;
	}
	memcpy(new_str, data, size);
	new_str[size] = '\0';
	
	/* Insert fuzzer contents here */
	gravity_delegate_t delegate = {.error_callback = report_error};
    
    // compile Gravity source code into bytecode
    gravity_compiler_t *compiler = gravity_compiler_create(&delegate);
    gravity_closure_t *closure = gravity_compiler_run(compiler, new_str, strlen(new_str), 0, true, true);
    /*if (!closure) {
        // an error occurred while compiling source code and it has already been reported by the report_error callback
        gravity_compiler_free(compiler);
		free(new_str);
        return 1;
    }*/
	free(new_str);
	gravity_compiler_free(compiler);
    return 0;
    gravity_vm *vm = gravity_vm_new(&delegate);
	/* - end of fuzzer contents  - */
	gravity_compiler_free(compiler);

	if (gravity_vm_runmain(vm, closure)) {
        // print result (INT) 30 in this simple example
        gravity_value_t result = gravity_vm_result(vm);
        gravity_value_dump(vm, result, NULL, 0);
    }
	
	free(new_str);
	gravity_vm_free(vm);
	gravity_core_free();
	return 0;
}