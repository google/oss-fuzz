# Using Ubuntu 16.04 because of breakage on Ubuntu 20.04.
# See https://github.com/google/oss-fuzz/issues/6291 for more details.
FROM gcr.io/oss-fuzz-base/base-builder:xenial
# Delete line above and uncomment line below to upgrade to 20.04.
# FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update
RUN apt-get install -y build-essential libncursesw5-dev \
	libreadline-dev libssl-dev libgdbm-dev \
	libc6-dev libsqlite3-dev tk-dev libbz2-dev \
	zlib1g-dev libffi-dev

RUN git clone https://github.com/python/cpython.git cpython3
WORKDIR cpython3
COPY build.sh $SRC/
