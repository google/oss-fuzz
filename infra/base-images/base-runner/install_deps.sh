#! /bin/bash
apt-get update && apt-get install -y \
    binutils \
    file \
    fonts-dejavu \
    git \
    libcap2 \
    python3 \
    python3-pip \
    python3-setuptools \
    rsync \
    unzip \
    wget \
    zip --no-install-recommends

case $(uname -m) in
    x86_64)
	apt-get install -y lib32gcc1 libc6-i386
        ;;
esac
