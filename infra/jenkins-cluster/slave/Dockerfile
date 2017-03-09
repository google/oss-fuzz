FROM openjdk:8-jdk
MAINTAINER Mike Aizatsky <aizatsky@google.com>

ARG JENKINS_REMOTING_VERSION=3.5

ENV DOCKER_BUCKET get.docker.com
ENV DOCKER_VERSION 1.13.1
ENV DOCKER_SHA256 97892375e756fd29a304bd8cd9ffb256c2e7c8fd759e12a55a6336e15100ad75
ENV DIND_COMMIT 3b5fac462d21ca164b3778647420016315289034


RUN apt-get update && apt-get upgrade -y
# Needed for our build environment.
RUN apt-get install -y zip git curl
RUN curl https://sdk.cloud.google.com | bash
ENV PATH "$PATH:/root/google-cloud-sdk/bin"

##########
# Docker in the Docker. Follows official docker:dind image
#

# https://github.com/docker/docker/blob/master/project/PACKAGERS.md#runtime-dependencies
RUN apt-get install -y \
  btrfs-progs \
  e2fsprogs \
  iptables \
  xfsprogs \
  ca-certificates \
  curl \
  openssl

# set up subuid/subgid so that "--userns-remap=default" works out-of-the-box
RUN set -x \
  && adduser --system --group dockremap \
  && echo 'dockremap:165536:65536' >> /etc/subuid \
  && echo 'dockremap:165536:65536' >> /etc/subgid

RUN set -x \
     && curl -fSL "https://${DOCKER_BUCKET}/builds/Linux/x86_64/docker-${DOCKER_VERSION}.tgz" -o docker.tgz \
     && echo "${DOCKER_SHA256} *docker.tgz" | sha256sum -c - \
     && tar -xzvf docker.tgz \
     && mv docker/* /usr/local/bin/ \
     && rmdir docker \
     && rm docker.tgz \
     && docker -v

RUN wget "https://raw.githubusercontent.com/docker/docker/${DIND_COMMIT}/hack/dind" -O /usr/local/bin/dind \
	&& chmod +x /usr/local/bin/dind

COPY dockerd-entrypoint.sh /usr/local/bin/

VOLUME /var/lib/docker
EXPOSE 2375

################
# JENKINS SLAVE

RUN curl --create-dirs -sSLo /usr/share/jenkins/slave.jar \
     https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/${JENKINS_REMOTING_VERSION}/remoting-${JENKINS_REMOTING_VERSION}.jar \
  && chmod 755 /usr/share/jenkins \
  && chmod 644 /usr/share/jenkins/slave.jar

RUN mkdir -p $HOME/.jenkins
VOLUME $HOME/.jenkins

VOLUME /workspace

COPY jenkins-slave /usr/local/bin/
COPY startup.sh /usr/local/bin/
ENTRYPOINT ["startup.sh"]

