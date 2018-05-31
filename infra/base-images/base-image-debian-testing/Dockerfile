FROM debian:testing

ENV DEBIAN_FRONTEND noninteractive
RUN echo 'deb-src http://deb.debian.org/debian testing main' >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y libc6-dev binutils libgcc-7-dev && \
    apt-get autoremove -y


ENV OUT=/out
ENV SRC=/src
ENV WORK=/work
ENV PATH="$PATH:/out"

RUN mkdir -p $OUT $SRC $WORK && chmod a+rwx $OUT $SRC $WORK
