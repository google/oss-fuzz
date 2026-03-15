FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y cmake ninja-build && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/hadipra5/weavebundle.git $SRC/weavebundle

WORKDIR $SRC/weavebundle

COPY build.sh $SRC/