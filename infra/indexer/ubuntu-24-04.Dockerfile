FROM gcr.io/oss-fuzz-base/base-clang-full:ubuntu-24-04

RUN mkdir /indexer
WORKDIR /indexer
COPY . /indexer

RUN apt-get update && apt-get install -y libsqlite3-dev make zlib1g-dev
RUN mkdir build && cd build && cmake .. && cmake --build . -j -v
