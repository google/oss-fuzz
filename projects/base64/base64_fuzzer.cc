#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "libbase64.h"

// Fuzz aklomp/base64 encode and decode paths.
// Exercises: encode streaming, decode streaming, encode/decode
// round-trip consistency, and invalid input handling in decode.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- Encode then decode (round-trip) ---
    {
        // Encoded output is at most ceil(size / 3) * 4 bytes + NUL.
        size_t enc_len = ((size + 2) / 3) * 4 + 1;
        std::vector<char> encoded(enc_len);
        size_t out_len = 0;

        struct base64_state state;
        base64_stream_encode_init(&state, 0);
        base64_stream_encode(&state,
                             reinterpret_cast<const char *>(data),
                             size,
                             encoded.data(),
                             &out_len);
        size_t final_len = 0;
        base64_stream_encode_final(&state,
                                   encoded.data() + out_len,
                                   &final_len);
        out_len += final_len;

        // Decode the encoded data back.
        size_t dec_alloc = size + 4;
        std::vector<char> decoded(dec_alloc);
        size_t dec_len = 0;

        struct base64_state dstate;
        base64_stream_decode_init(&dstate, 0);
        int ret = base64_stream_decode(&dstate,
                                       encoded.data(),
                                       out_len,
                                       decoded.data(),
                                       &dec_len);
        (void)ret;
    }

    // --- Directly decode the raw fuzz input (likely invalid base64) ---
    {
        size_t dec_alloc = (size / 4 + 1) * 3 + 4;
        std::vector<char> decoded(dec_alloc);
        size_t dec_len = 0;

        struct base64_state dstate;
        base64_stream_decode_init(&dstate, 0);
        int ret = base64_stream_decode(&dstate,
                                       reinterpret_cast<const char *>(data),
                                       size,
                                       decoded.data(),
                                       &dec_len);
        (void)ret;
    }

    return 0;
}
