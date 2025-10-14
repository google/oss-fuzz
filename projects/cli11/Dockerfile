FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth=1 https://github.com/CLIUtils/CLI11.git $SRC/cli11
COPY build.sh $SRC/
COPY fuzzers $SRC/fuzzers
WORKDIR $SRC
