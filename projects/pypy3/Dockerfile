FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && \
    apt-get install -y gcc make libffi-dev pkg-config \
    zlib1g-dev libbz2-dev libsqlite3-dev libncurses5-dev \
    libexpat1-dev libssl-dev libgdbm-dev tk-dev libgc-dev \
    liblzma-dev libncursesw5-dev \
    pypy

RUN git clone --depth 1 --branch py3.11 https://github.com/pypy/pypy.git pypy
RUN git clone --depth 1 --branch main https://github.com/StanFromIreland/pypy-fuzz.git
WORKDIR pypy
COPY build.sh $SRC/
