FROM ossfuzz/base-builder
MAINTAINER nickm@torproject.org
RUN apt-get install -y zlib1g zlib1g-dev libevent-dev libevent-2.0 openssl autoconf automake libssl-dev make libc++-dev
RUN true && true && git clone https://git.torproject.org/nickm/tor.git -b combined-fuzzing-v3
WORKDIR tor
COPY build.sh $SRC/
