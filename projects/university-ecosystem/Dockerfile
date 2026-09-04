FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY . $SRC/university_ecosystem
WORKDIR $SRC/university_ecosystem

COPY infra/oss-fuzz/build.sh $SRC/
RUN chmod +x $SRC/build.sh
