############################################################
# Dockerfile to build Laika BOSS container images
# Based on Ubuntu
############################################################
FROM ubuntu
MAINTAINER Jason Loveland <@jasonloveland>

# Set correct environment variables.
ENV HOME /home/root

ADD . /home/root/Code
WORKDIR /home/root/Code

# installation
RUN apt-get update && apt-get install -y \
    build-essential \
    libfuzzy-dev \
    libimage-exiftool-perl \
    liblzma5 \
    libzmq3 \
    python-cffi \
    python-dev \
    python-gevent \
    python-ipy \
    python-m2crypto \
    python-msgpack \
    python-pefile \
    python-pexpect \
    python-pip \
    python-progressbar \
    python-pyclamd \
    python-yara \
    python-zmq \
    unrar-free \
    unzip \
    wget \
    yara \
    zip
RUN pip install --upgrade pip virtualenv
RUN pip install fluent-logger \
    interruptingcow \
    olefile \
    py-unrar2 \
    pylzma \
    ssdeep
RUN wget https://github.com/smarnach/pyexiftool/archive/master.zip && \
    unzip master.zip && \
    cd pyexiftool-master && \
    python setup.py build && \
    python setup.py install
RUN cd /usr/bin/; \
    wget http://stedolan.github.io/jq/download/linux64/jq; \
    chmod u+x jq;

# make laikaboss executable and run the service
RUN chmod u+x ./laikad.py; \
    chmod u+x ./laika.py; \
    chmod u+x ./cloudscan.py; \
    sync; \
    ./laikad.py;

# allow users to execute laika drom docker run
ENTRYPOINT ./laika.py
