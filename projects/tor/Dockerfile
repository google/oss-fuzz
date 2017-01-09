FROM ossfuzz/base-builder
MAINTAINER nickm@torproject.org
RUN apt-get install -y zlib1g zlib1g-dev libevent-dev libevent-2.0 openssl autoconf automake
RUN git clone https://git.torproject.org/tor.git
WORKDIR tor
COPY build.sh $SRC/
