FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update

RUN git clone --depth 1 https://github.com/Alan32Liu/github-scarecrow.git $SRC/github-scarecrow
WORKDIR $SRC/github-scarecrow
COPY build.sh $SRC/