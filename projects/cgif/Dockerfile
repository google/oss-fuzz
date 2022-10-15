FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y python3-pip zip
RUN pip3 install meson ninja
RUN git clone --depth 1 https://github.com/dloebl/cgif.git
WORKDIR cgif
COPY build.sh $SRC/
