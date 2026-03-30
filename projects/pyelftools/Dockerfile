FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone --depth 1 https://github.com/eliben/pyelftools.git

WORKDIR $SRC/pyelftools

COPY *.py $SRC/
COPY build.sh $SRC/
