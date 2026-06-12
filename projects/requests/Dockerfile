FROM gcr.io/oss-fuzz-base/base-builder-python
RUN pip3 install atheris requests
COPY . $SRC/requests
COPY build.sh $SRC/
WORKDIR $SRC/requests
