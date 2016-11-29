#ifndef CHEWING_FUZZER_COMMON_H
#define CHEWING_FUZZER_COMMON_H

#include <stddef.h>
#include <stdint.h>

const uint8_t* fuzz_ptr;
const uint8_t* fuzz_input;
size_t fuzz_size;

int stress_main(int argc, char** argv);

#endif
