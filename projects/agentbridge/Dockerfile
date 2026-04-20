FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN git clone --depth 1 https://github.com/catatafishen/agentbridge.git /src/agentbridge
WORKDIR /src/agentbridge

COPY build.sh $SRC/
