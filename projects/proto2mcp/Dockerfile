FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/protocgen/proto2mcp $SRC/proto2mcp
WORKDIR $SRC/proto2mcp
COPY build.sh $SRC/
