/*
 * faiss_fuzz_harness.cpp -- v4 libFuzzer harness for FAISS (OSS-Fuzz ready).
 *
 * Input layout: [4-byte LE index_len][index bytes][query bytes]
 *
 * Routes:
 *   - read_index            (75+ float index types)
 *   - read_index_binary     (binary index types)
 *   - read_ProductQuantizer (PQ deserializer)
 *
 * After a successful float read_index, exercises:
 *   search, range_search, reconstruct, reconstruct_n, assign,
 *   compute_residual, sa_decode (when codec is supported).
 *
 * After a successful binary read_index_binary, exercises:
 *   search, assign, reconstruct.
 *
 * Sanity caps prevent query-driven OOMs from drowning real findings.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

#include <faiss/index_io.h>
#include <faiss/Index.h>
#include <faiss/IndexBinary.h>
#include <faiss/impl/io.h>
#include <faiss/impl/ProductQuantizer.h>
#include <faiss/impl/AuxIndexStructures.h>

struct MemReader : faiss::IOReader {
    const uint8_t *data;
    size_t size;
    size_t pos;

    MemReader(const uint8_t *d, size_t s) : data(d), size(s), pos(0) {
        name = "fuzz_input";
    }

    size_t operator()(void *ptr, size_t unitsize, size_t nitems) override {
        size_t bytes = unitsize * nitems;
        if (pos + bytes > size) {
            bytes = (pos < size) ? size - pos : 0;
        }
        if (bytes > 0) {
            memcpy(ptr, data + pos, bytes);
            pos += bytes;
        }
        return bytes / unitsize;
    }

    int filedescriptor() override { return -1; }
};

#define FAISS_FUZZ_MAX_SIZE   (4u * 1024u * 1024u)
#define FAISS_FUZZ_MAX_D       256
#define FAISS_FUZZ_MAX_NTOTAL  5000
#define FAISS_FUZZ_MAX_K       16
#define FAISS_FUZZ_MAX_NQ      4

static void scrub_floats(std::vector<float> &v) {
    for (float &x : v) {
        if (!(x == x) || x > 1e30f || x < -1e30f) x = 0.0f;
    }
}

static void exercise_runtime(faiss::Index *idx,
                             const uint8_t *qbytes, size_t qsize) {
    if (!idx) return;
    int d = idx->d;
    faiss::idx_t ntotal = idx->ntotal;
    if (d <= 0 || d > FAISS_FUZZ_MAX_D) return;
    if (ntotal < 0 || ntotal > FAISS_FUZZ_MAX_NTOTAL) return;

    size_t nq = 1;
    if (qsize >= (size_t)d * sizeof(float) * 2) nq = 2;
    if (qsize >= (size_t)d * sizeof(float) * 4) nq = FAISS_FUZZ_MAX_NQ;

    std::vector<float> queries((size_t)nq * d, 0.0f);
    size_t copy_bytes = std::min(qsize, queries.size() * sizeof(float));
    if (copy_bytes > 0) memcpy(queries.data(), qbytes, copy_bytes);
    scrub_floats(queries);

    faiss::idx_t k = 1 + (qbytes && qsize ? qbytes[0] % FAISS_FUZZ_MAX_K : 0);
    if (k > ntotal && ntotal > 0) k = ntotal;
    if (k <= 0) k = 1;

    /* knn search -- distance/heap/sort kernels */
    try {
        std::vector<float> distances((size_t)nq * k, 0.0f);
        std::vector<faiss::idx_t> labels((size_t)nq * k, -1);
        idx->search(nq, queries.data(), k, distances.data(), labels.data());
    } catch (...) {}

    /* assign -- coarse quantizer paths */
    try {
        std::vector<faiss::idx_t> labels(nq, -1);
        idx->assign(nq, queries.data(), labels.data(), 1);
    } catch (...) {}

    /* range_search -- different scanner path */
    try {
        faiss::RangeSearchResult rsr(nq);
        idx->range_search(nq, queries.data(), 1.0f, &rsr);
    } catch (...) {}

    /* reconstruct -- decoder paths (PQ/SQ/residual) */
    if (ntotal > 0) {
        try {
            std::vector<float> recon(d, 0.0f);
            faiss::idx_t id = qsize ? (faiss::idx_t)(qbytes[qsize - 1] % ntotal) : 0;
            idx->reconstruct(id, recon.data());
        } catch (...) {}

        /* reconstruct_n -- batched decoder path */
        try {
            faiss::idx_t batch = std::min<faiss::idx_t>(8, ntotal);
            std::vector<float> recon((size_t)batch * d, 0.0f);
            idx->reconstruct_n(0, batch, recon.data());
        } catch (...) {}
    }

    /* compute_residual -- subtraction against quantizer */
    try {
        std::vector<float> resid(d, 0.0f);
        if (ntotal > 0) {
            faiss::idx_t id = qsize ? (faiss::idx_t)(qbytes[0] % ntotal) : 0;
            idx->compute_residual(queries.data(), resid.data(), id);
        }
    } catch (...) {}

    /* sa_decode -- standalone codec path */
    try {
        size_t code_size = idx->sa_code_size();
        if (code_size > 0 && code_size < 4096) {
            std::vector<uint8_t> code(code_size, 0);
            if (qsize >= code_size) memcpy(code.data(), qbytes, code_size);
            std::vector<float> recon(d, 0.0f);
            idx->sa_decode(1, code.data(), recon.data());
        }
    } catch (...) {}
}

static void exercise_runtime_binary(faiss::IndexBinary *idx,
                                    const uint8_t *qbytes, size_t qsize) {
    if (!idx) return;
    int d = idx->d;
    faiss::idx_t ntotal = idx->ntotal;
    if (d <= 0 || d > FAISS_FUZZ_MAX_D * 8) return;
    if (d % 8 != 0) return;
    if (ntotal < 0 || ntotal > FAISS_FUZZ_MAX_NTOTAL) return;

    size_t code_size = (size_t)d / 8;
    size_t nq = 1;
    if (qsize >= code_size * 2) nq = 2;

    std::vector<uint8_t> queries(nq * code_size, 0);
    size_t copy_bytes = std::min(qsize, queries.size());
    if (copy_bytes > 0) memcpy(queries.data(), qbytes, copy_bytes);

    faiss::idx_t k = 1 + (qbytes && qsize ? qbytes[0] % FAISS_FUZZ_MAX_K : 0);
    if (k > ntotal && ntotal > 0) k = ntotal;
    if (k <= 0) k = 1;

    /* knn search -- hamming kernels */
    try {
        std::vector<int32_t> distances((size_t)nq * k, 0);
        std::vector<faiss::idx_t> labels((size_t)nq * k, -1);
        idx->search(nq, queries.data(), k, distances.data(), labels.data());
    } catch (...) {}

    /* assign */
    try {
        std::vector<faiss::idx_t> labels(nq, -1);
        idx->assign(nq, queries.data(), labels.data(), 1);
    } catch (...) {}

    /* reconstruct */
    if (ntotal > 0) {
        try {
            std::vector<uint8_t> recon(code_size, 0);
            faiss::idx_t id = qsize ? (faiss::idx_t)(qbytes[qsize - 1] % ntotal) : 0;
            idx->reconstruct(id, recon.data());
        } catch (...) {}
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > FAISS_FUZZ_MAX_SIZE) return 0;

    uint32_t index_len;
    memcpy(&index_len, data, 4);
    const uint8_t *rest = data + 4;
    size_t rest_size = size - 4;
    if (index_len == 0 || index_len > rest_size) {
        index_len = rest_size;
    }
    const uint8_t *index_bytes = rest;
    const uint8_t *query_bytes = rest + index_len;
    size_t query_size = rest_size - index_len;

    if (index_len < 4) return 0;

    char magic[4];
    memcpy(magic, index_bytes, 4);
    bool is_binary = (magic[0] == 'I' && magic[1] == 'B');
    bool is_pq = (magic[0] == 'I' && magic[1] == 'x' &&
                  magic[2] == 'P' && (magic[3] == 'q' || magic[3] == 'Q'));

    try {
        if (is_binary) {
            MemReader reader(index_bytes, index_len);
            std::unique_ptr<faiss::IndexBinary> idx(
                faiss::read_index_binary(&reader));
            exercise_runtime_binary(idx.get(), query_bytes, query_size);
        } else if (is_pq) {
            MemReader reader(index_bytes, index_len);
            std::unique_ptr<faiss::ProductQuantizer> pq(
                faiss::read_ProductQuantizer(&reader));
        } else {
            MemReader reader(index_bytes, index_len);
            std::unique_ptr<faiss::Index> idx(
                faiss::read_index(&reader));
            exercise_runtime(idx.get(), query_bytes, query_size);
        }
    } catch (...) {}

    return 0;
}
