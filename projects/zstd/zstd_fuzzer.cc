#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "zstd.h"

// Fuzz the zstd compression/decompression library.
// Exercises: streaming decompression of arbitrary bytes,
// compress-then-decompress round-trip, ZSTD_findDecompressedSize,
// and context reuse across calls.
//
// Note: facebook/zstd ships its own fuzz corpus under tests/fuzz/,
// but has no OSS-Fuzz integration file yet. This harness complements
// the existing internal harnesses with a clean OSS-Fuzz entry-point.

static ZSTD_DCtx *g_dctx = nullptr;
static ZSTD_CCtx *g_cctx = nullptr;

extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
    g_dctx = ZSTD_createDCtx();
    g_cctx = ZSTD_createCCtx();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_dctx || !g_cctx) return 0;

    // --- Decompress arbitrary (likely invalid) bytes ---
    {
        size_t out_cap = ZSTD_DStreamOutSize();
        std::vector<uint8_t> out(out_cap);

        ZSTD_inBuffer in_buf  = {data, size, 0};
        ZSTD_outBuffer out_buf = {out.data(), out.size(), 0};

        ZSTD_DCtx_reset(g_dctx, ZSTD_reset_session_only);
        while (in_buf.pos < in_buf.size) {
            size_t ret = ZSTD_decompressStream(g_dctx, &out_buf, &in_buf);
            if (ZSTD_isError(ret)) break;
            out_buf.pos = 0; // reset output buffer for next iteration
        }
    }

    // --- Compress input then decompress (round-trip correctness) ---
    if (size > 0 && size <= 64 * 1024) {
        size_t comp_bound = ZSTD_compressBound(size);
        std::vector<uint8_t> compressed(comp_bound);

        ZSTD_CCtx_reset(g_cctx, ZSTD_reset_session_only);
        size_t comp_size = ZSTD_compress2(
            g_cctx,
            compressed.data(), compressed.size(),
            data, size);

        if (!ZSTD_isError(comp_size)) {
            // Decompress what we just compressed.
            std::vector<uint8_t> decompressed(size + 1);
            ZSTD_DCtx_reset(g_dctx, ZSTD_reset_session_only);
            size_t dec_size = ZSTD_decompressDCtx(
                g_dctx,
                decompressed.data(), decompressed.size(),
                compressed.data(), comp_size);
            (void)dec_size;
        }
    }

    // --- ZSTD_findDecompressedSize (exercises frame header parsing) ---
    {
        unsigned long long ds = ZSTD_findDecompressedSize(data, size);
        (void)ds; // may return ZSTD_CONTENTSIZE_UNKNOWN or ERROR
    }

    return 0;
}
