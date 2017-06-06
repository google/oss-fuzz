FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER paras.chetal@gmail.com

RUN apt-get update && apt-get -y install build-essential automake libtool git python

WORKDIR qubes-os

RUN git clone --depth 1 https://github.com/qubesos/qubes-builder-debian.git $SRC/qubes-os/builder-debian && \
    echo "deb [arch=amd64] http://deb.qubes-os.org/r4.0/vm stretch main" >> /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://deb.qubes-os.org/r4.0/vm stretch-testing main" >> /etc/apt/sources.list && \
    apt-key add $SRC/qubes-os/builder-debian/keys/qubes-debian-r4.0.asc && \
    apt-get update

RUN git clone --depth 1 https://github.com/paraschetal/qubes-linux-utils.git $SRC/qubes-os/linux-utils && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --build-depends $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --qubes-build-depends debian $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --qubes-build-depends stretch $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install

COPY build.sh $SRC/