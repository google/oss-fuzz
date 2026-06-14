FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/rhysmcneill/ssmctl $GOPATH/src/ssmctl
WORKDIR $GOPATH/src/ssmctl

COPY build.sh /
RUN chmod +x /build.sh
ENTRYPOINT ["/build.sh"]
