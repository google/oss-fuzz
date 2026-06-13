FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y --no-install-recommends make
RUN git clone --depth 1 https://github.com/InauguralSystems/EigenScript.git eigenscript
WORKDIR eigenscript
COPY build.sh $SRC/
