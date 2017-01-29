FROM ossfuzz/base-builder
MAINTAINER jonathan.foote@gmail.com
RUN apt-get install -y make autoconf automake libtool cmake zlib1g-dev pkg-config libssl-dev
RUN git clone --depth 1 https://github.com/h2o/h2o # or use other version control
WORKDIR h2o
COPY build.sh $SRC/
COPY fixup.patch $SRC/
