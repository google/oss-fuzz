FROM gcr.io/oss-fuzz-base/base-clang-full:ubuntu-24-04

RUN mkdir /indexer
WORKDIR /indexer
COPY . /indexer

# Best-effort: the indexer tracks LLVM head while base-clang pins an older LLVM,
# so it regularly fails to compile. Do not let that block the base image builds.
# base-builder checks whether a real binary came out. Keep the '|| true'.
# https://github.com/google/oss-fuzz/issues/16141
RUN apt-get update && apt-get install -y libsqlite3-dev make zlib1g-dev || true
RUN (mkdir build && cd build && cmake .. && cmake --build . -j -v) || true
RUN mkdir -p /indexer/build && touch /indexer/build/indexer
