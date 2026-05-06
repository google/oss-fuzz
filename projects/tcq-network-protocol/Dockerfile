FROM gcr.io/oss-fuzz-base/base-builder-go:v1
RUN git clone --depth 1 https://github.com/NguyenHien-8/TCQ-Network-Protocol $SRC/TCQ-Network-Protocol
WORKDIR $SRC/TCQ-Network-Protocol
COPY build.sh $SRC/