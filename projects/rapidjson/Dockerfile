FROM gcr.io/oss-fuzz-base/base-builder

RUN git clone --depth 1 https://github.com/Tencent/rapidjson.git

WORKDIR rapidjson
COPY build.sh rapidjson_fuzzer.cc $SRC/
