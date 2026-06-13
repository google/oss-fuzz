#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "utf8proc.h"
}

// Fuzz the utf8proc Unicode / UTF-8 library.
// Exercises: iterating over codepoints, normalization (NFC, NFD,
// NFKC, NFKD), case folding, character category queries, and
// utf8proc_map (the high-level transformation entry point).
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const utf8proc_uint8_t *str =
        reinterpret_cast<const utf8proc_uint8_t *>(data);

    // --- Codepoint iteration ---
    {
        utf8proc_ssize_t pos = 0;
        utf8proc_int32_t cp;
        while (pos < static_cast<utf8proc_ssize_t>(size)) {
            utf8proc_ssize_t n =
                utf8proc_iterate(str + pos, size - pos, &cp);
            if (n <= 0) break;
            if (cp >= 0) {
                // Query properties for each valid codepoint.
                (void)utf8proc_category(cp);
                (void)utf8proc_category_string(cp);
                (void)utf8proc_charwidth(cp);
                (void)utf8proc_islower(cp);
                (void)utf8proc_isupper(cp);
                utf8proc_int32_t lower = utf8proc_tolower(cp);
                utf8proc_int32_t upper = utf8proc_toupper(cp);
                (void)lower;
                (void)upper;
            }
            pos += n;
        }
    }

    // --- High-level map / normalization ---
    static const utf8proc_option_t norm_flags[] = {
        UTF8PROC_COMPOSE,
        UTF8PROC_DECOMPOSE,
        static_cast<utf8proc_option_t>(
            UTF8PROC_COMPOSE | UTF8PROC_COMPAT),
        static_cast<utf8proc_option_t>(
            UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT),
        static_cast<utf8proc_option_t>(
            UTF8PROC_COMPOSE | UTF8PROC_CASEFOLD),
    };

    for (utf8proc_option_t flags : norm_flags) {
        utf8proc_uint8_t *out = nullptr;
        utf8proc_ssize_t result =
            utf8proc_map(str, static_cast<utf8proc_ssize_t>(size),
                         &out, flags);
        if (result >= 0 && out) {
            free(out);
        }
    }

    // --- Encode a single arbitrary codepoint ---
    if (size >= 3) {
        utf8proc_int32_t cp =
            static_cast<utf8proc_int32_t>(
                (static_cast<uint32_t>(data[0]) << 16) |
                (static_cast<uint32_t>(data[1]) << 8) |
                static_cast<uint32_t>(data[2]));
        utf8proc_uint8_t buf[4];
        (void)utf8proc_encode_char(cp, buf);
    }

    return 0;
}
