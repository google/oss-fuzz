#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "baby.h"


// Fuzz target function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Allocate memory for the input string
    char *input = malloc(size + 1);
    if (input == NULL) {
        // Handle memory allocation failure
        return 1;
    }
    
    // Copy the fuzzed input and null-terminate the string
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the target function with the fuzzed input
    badFunction(input);

    // Free allocated memory
    free(input);
    
    return 0;
}

