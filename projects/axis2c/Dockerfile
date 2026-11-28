FROM gcr.io/oss-fuzz-base/base-builder 
RUN apt-get update && apt-get install -y \
    autoconf automake libtool pkg-config \
    libxml2-dev libjson-c-dev libssl-dev zlib1g-dev
RUN git clone --depth 1 https://github.com/apache/axis-axis2-c-core.git axis2c         
WORKDIR axis2c
COPY build.sh $SRC/
