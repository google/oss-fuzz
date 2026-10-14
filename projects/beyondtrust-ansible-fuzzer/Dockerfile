FROM gcr.io/oss-fuzz-base/base-builder-python

# Install system dependencies and add the deadsnakes PPA for Python 3.11
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update

# Install Python 3.11 and its associated tools
RUN apt-get install -y \
    python3.11 \
    python3.11-distutils \
    python3.11-venv \
    && apt-get clean

# Install pip for Python 3.11 and upgrade it
RUN python3.11 -m ensurepip --upgrade
RUN python3.11 -m pip install --upgrade pip

# Update symbolic links to make Python 3.11 the default
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3
RUN ln -sf /usr/bin/python3.11 /usr/bin/python
RUN ln -sf /usr/bin/pip3 /usr/bin/pip

# Enable the following COPY command only locally for dev/testing purposes
# Need to previously have cloned ps-integration-ansible
# COPY ps-integration-ansible/beyondtrust/secrets_safe /src/ps-integration-ansible/beyondtrust/secrets_safe

WORKDIR /src

RUN pip install -r /src/ps-integration-ansible/beyondtrust/secrets_safe/requirements.txt
RUN pip install atheris