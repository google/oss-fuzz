FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/rhysmcneill/ssmctl $GOPATH/src/github.com/rhysmcneill/ssmctl && \
    cd $GOPATH/src/github.com/rhysmcneill/ssmctl

COPY build.sh /src/

