FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake

RUN git clone --depth 1 https://github.com/leethomason/tinyxml2.git

WORKDIR tinyxml2
COPY build.sh tinyxml2_fuzzer.cc $SRC/
