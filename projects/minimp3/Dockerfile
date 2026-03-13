FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone --depth 1 https://github.com/lieff/minimp3.git $SRC/minimp3
WORKDIR $SRC/minimp3
COPY build.sh fuzz_decode_frame.c fuzz_decode_buf.c fuzz_decode_ex.c mp3.dict $SRC/
