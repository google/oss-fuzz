FROM gcr.io/oss-fuzz-base/base-builder

ENV CLUSTERFUZZLITE=1
RUN apt-get update && apt-get install -y bison libssl-dev libevent-dev
RUN git clone --depth 1 https://github.com/openiked/openiked-portable.git openiked-portable
RUN git clone --depth 1 https://github.com/openiked/openiked-fuzzing.git openiked-fuzzing
WORKDIR openiked-portable
COPY build.sh $SRC/
