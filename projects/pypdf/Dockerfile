FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone --depth 1 https://github.com/py-pdf/pypdf.git pypdf

WORKDIR $SRC/pypdf

COPY build.sh pypdf_fuzzer.py $SRC/