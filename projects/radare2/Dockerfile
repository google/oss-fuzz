FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER zlowram@gmail.com
RUN apt-get update
RUN git clone --depth 1 https://github.com/radare/radare2 radare2
RUN git clone --depth 1 https://github.com/radare/radare2-regressions radare2-regressions
WORKDIR radare2
COPY build.sh $SRC/
COPY *.options $SRC/

