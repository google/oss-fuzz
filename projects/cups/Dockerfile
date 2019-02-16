FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER skau@chromium.org
RUN apt-get update && apt-get install -y libgnutls-dev liblcms2-dev
RUN git clone https://github.com/apple/cups.git cups
WORKDIR cups
COPY build.sh $SRC/
