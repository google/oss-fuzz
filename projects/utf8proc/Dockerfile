FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make

RUN git clone --depth 1 https://github.com/JuliaStrings/utf8proc.git

WORKDIR utf8proc
COPY build.sh utf8proc_fuzzer.cc $SRC/
