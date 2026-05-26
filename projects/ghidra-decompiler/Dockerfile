# OSS-Fuzz build container for the GayHydra decompiler harnesses.
# See docs/security/OSS_FUZZ.md.

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    bison \
    flex \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/CryptoJones/GayHydra.git $SRC/ghidra
WORKDIR $SRC/ghidra

COPY build.sh $SRC/
