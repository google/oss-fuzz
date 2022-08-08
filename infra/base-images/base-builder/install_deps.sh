#! /bin/bash


case $(uname -m) in
    x86_64)
	dpkg --add-architecture i386
        ;;
esac

apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:git-core/ppa && \
    apt-get update && \
    apt-get install -y \
        binutils-dev \
        build-essential \
        curl \
        wget \
        git \
        jq \
        patchelf \
        rsync \
        subversion \
        zip

case $(uname -m) in
    x86_64)
	apt-get install -y libc6-dev-i386
        ;;
esac
