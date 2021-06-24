FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update
RUN git clone https://github.com/radareorg/radare2 radare2
RUN git clone https://github.com/radareorg/radare2-fuzz radare2-fuzz
WORKDIR radare2
COPY build.sh $SRC/
COPY *.options $SRC/

