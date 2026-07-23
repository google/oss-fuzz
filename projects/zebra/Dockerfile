# OSS-Fuzz build environment for the Zebra coverage-guided fuzz suite.
#
# base-builder-rust ships the nightly toolchain + cargo-fuzz pre-installed
# (https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/).
FROM gcr.io/oss-fuzz-base/base-builder-rust

# System deps the Zebra workspace needs beyond base-builder-rust:
#   - cmake / clang / libclang-dev : build the zcash_script C/C++ library reached
#     through the zebra-script FFI (script_verify / script_flag_matrix). rocksdb's
#     librocksdb-sys always runs bindgen, so libclang is a hard, workspace-wide
#     build dependency even when a system RocksDB is linked.
#   - protobuf-compiler : zebra-rpc pulls tonic, whose build script invokes protoc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake clang libclang-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/robustfengbin/zebra-fuzz-m3 $SRC/zebra-fuzz
WORKDIR $SRC/zebra-fuzz
COPY build.sh $SRC/
