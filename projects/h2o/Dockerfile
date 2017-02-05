FROM ossfuzz/base-builder
MAINTAINER jonathan.foote@gmail.com
RUN apt-get install -y make autoconf automake libtool cmake zlib1g-dev pkg-config libssl-dev
RUN git clone https://github.com/h2o/h2o
WORKDIR h2o
COPY build.sh $SRC/
COPY *.options $SRC/
