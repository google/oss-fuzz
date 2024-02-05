FROM gcr.io/oss-fuzz-base/base-builder
RUN git clone https://github.com/VinhPham2106/babyfuzz.git
COPY build.sh baby_overflow.c fuzz_target.c baby.h $SRC/
