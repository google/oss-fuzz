# Docker image to run CIFuzz in.

FROM ubuntu:16.04

RUN apt-get update && apt-get install -y git \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    software-properties-common \
    python3


RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && apt-key fingerprint 0EBFCD88
RUN add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   xenial \
   stable"

RUN apt-get update && apt-get install docker-ce docker-ce-cli containerd.io -y

ENV OSS_FUZZ_ROOT=/opt/oss-fuzz
RUN git clone https://github.com/google/oss-fuzz.git ${OSS_FUZZ_ROOT}
