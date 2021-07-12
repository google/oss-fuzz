#include "fuzzlpm/proto/profile.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

extern "C" void  LPMFuzzerTestOneInput(const uint8_t *buffer, size_t size);

DEFINE_PROTO_FUZZER(const perftools::profiles::Profile& input) {
    size_t size = input.ByteSizeLong();
    if (size > 0) {
        uint8_t *buffer = (uint8_t *) malloc(size);
        input.SerializeToArray((uint8_t *) buffer, size);
        LPMFuzzerTestOneInput(buffer, size);
        free(buffer);
    }
}
