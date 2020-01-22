FROM gcr.io/oss-fuzz-base/base-builder

ENV GOPATH /gopath

RUN go get -u -d github.com/dvyukov/go-fuzz/...
RUN go get github.com/ianlancetaylor/demangle

RUN git clone --depth 1 https://github.com/kubernetes/kubernetes.git /gopath/src/k8s.io/kubernetes

WORKDIR /gopath/src/k8s.io/kubernetes

COPY build.sh $SRC/build.sh
