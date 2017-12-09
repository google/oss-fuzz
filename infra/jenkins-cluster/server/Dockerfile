FROM jenkins/jenkins:lts
USER root

RUN mkdir /var/secrets
RUN apt-get -y update && apt-get -y upgrade && apt-get -y install python-dev virtualenv python-pip build-essential

WORKDIR /
RUN wget https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.zip
RUN unzip google-cloud-sdk.zip

RUN /google-cloud-sdk/install.sh --usage-reporting=false --bash-completion=false --disable-installation-options
RUN /google-cloud-sdk/bin/gcloud -q components install alpha beta
RUN /google-cloud-sdk/bin/gcloud -q components update

RUN chown -R jenkins:jenkins /google-cloud-sdk

USER jenkins
ENV JENKINS_OPTS --httpPort=8080 --httpsPort=8082 --httpsCertificate=/var/secrets/cert.pem --httpsPrivateKey=/var/secrets/cert.key
ENV PATH=$PATH:/google-cloud-sdk/bin
