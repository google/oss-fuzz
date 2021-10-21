FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone --depth 1 --branch master \
        https://github.com/martinblech/xmltodict.git

WORKDIR xmltodict
COPY build.sh unparse_parse_fuzzer.py $SRC/
