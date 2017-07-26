FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER jeanpierreda@google.com
# Just installing python3-dev for its dependencies. We'll build our own copy.
# (apt-get build-dep fails for whatever reason.)
RUN apt-get update && apt-get install -y libtool python3-dev zlib1g-dev build-essential
RUN git clone --depth 1 https://github.com/python/cpython.git cpython
COPY build.sh $SRC/
