// Heuristic: TestConverterPrompt :: Target: 
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CGLTF_IMPLEMENTATION
#include "cgltf.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }

    cgltf_options options;
	memset(&options, 0, sizeof(cgltf_options));
	cgltf_data* parsed_data = NULL;
	cgltf_result result;

    // Parse input data
    result = cgltf_parse(&options, data, size, &parsed_data);

    if (result == cgltf_result_success) {
        result = cgltf_validate(parsed_data);
    }

    if (result == cgltf_result_success) {
        // Use the parsed data in some way
        // For example, print file type and mesh count
		printf("Type: %u\n", parsed_data->file_type);
		printf("Meshes: %u\n", (unsigned)parsed_data->meshes_count);
    }

    cgltf_free(parsed_data);

    return 0;
}
