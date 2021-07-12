#include <stdint.h>
#include <string>

#include <libpostal/libpostal.h>


struct PostalState {
    PostalState() {
        if (!libpostal_setup() || !libpostal_setup_parser()) {
            exit(EXIT_FAILURE);
        }
        options = libpostal_get_address_parser_default_options();
    }

    libpostal_address_parser_options_t options;
};

PostalState kPostalState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string storage(reinterpret_cast<const char *>(data), size);
    libpostal_address_parser_response_t *parsed = libpostal_parse_address(const_cast<char *>(storage.c_str()), kPostalState.options);
    if (parsed) {
        // Touch all the components to ensure they point to valid memory.
        std::string value;
        for (size_t i = 0; i < parsed->num_components; i++) {
            value += parsed->labels[i];
            value += parsed->components[i];
        }
        libpostal_address_parser_response_destroy(parsed);
    }

    return 0;
}
