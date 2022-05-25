FROM gcr.io/oss-fuzz-base/base-builder-python:v1
RUN apt-get update && apt-get install -y make autoconf automake libtool

COPY . $SRC/Dvpwa
WORKDIR Dvpwa

RUN pip3 install --upgrade pip
RUN pip3 install idna --force


RUN apt-get install -y \
    libc6-dev \
    libc++-dev \
    gcc \
    g++ \
    make \
    wget \
    gdb \
    llvm-dev \
    llvm \
    clang \
    libasan
