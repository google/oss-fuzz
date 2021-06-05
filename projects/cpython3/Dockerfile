FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update
RUN apt-get install -y build-essential libncursesw5-dev \
	libreadline-dev libssl-dev libgdbm-dev \
	libc6-dev libsqlite3-dev tk-dev libbz2-dev \
	zlib1g-dev libffi-dev

RUN git clone https://github.com/python/cpython.git cpython3
WORKDIR cpython3
COPY build.sh $SRC/
