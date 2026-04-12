FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get install -y build-essential libncursesw5-dev \
    libreadline-dev libssl-dev libgdbm-dev \
    libc6-dev libsqlite3-dev tk-dev libbz2-dev \
    zlib1g-dev libffi-dev pkg-config liblzma-dev

RUN git clone --depth 1 --branch main https://github.com/pypy/pypy.git pypy
RUN git clone --depth 1 --branch main https://github.com/StanFromIreland/pypy-fuzz.git
WORKDIR pypy
COPY build.sh $SRC/
