# This Docker image encapsulates the Laika BOSS: Object Scanning System by 
# Lockheed Martin Corporation from https://github.com/lmco/laikaboss 
#
# To run this image after installing Docker using a standalone instance, use a command like 
# the following, replacing “~/laikaboss-workdir" with the path to the location of your 
# Laika BOSS working directory:
#
# sudo docker run --rm -it -v ~/laikaboss-workdir:/home/nonroot/workdir wzod/laikaboss
#
# To run this image using a networked instance, use a command like this:
#
# sudo docker run --rm -it -p 5558:5558 -v ~/laikaboss-workdir:/home/nonroot/workdir wzod/laikaboss
#
# Before running Laika BOSS, create the  ~/laikaboss-workdir and make it world-accessible
# (“chmod a+xwr").
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM ubuntu:14.04
MAINTAINER Zod (@wzod)

ENV DEBIAN_FRONTEND noninteractive

USER root
RUN apt-get -y install software-properties-common && \
  apt-add-repository -y multiverse && \
  apt-get -qq update && apt-get install -y \
  automake \
  build-essential \
  git \
  jq \
  libfuzzy-dev \
  libimage-exiftool-perl \
  liblzma5 \
  libtool \
  libzmq3 \
  make \
  python-cffi \
  python-dev \
  python-gevent \
  python-ipy \
  python-m2crypto \
  python-msgpack \
  python-pexpect \
  python-pip \
  python-progressbar \
  python-pyclamd \
  python-zmq \
  unrar \
  unzip \
  wget

# Retrieve current version of Yara via wget, verify known good hash and install Yara
RUN cd /tmp && \
  wget -O yarav3.4.0.tar.gz "https://github.com/plusvic/yara/archive/v3.4.0.tar.gz" && \
  echo 528571ff721364229f34f6d1ff0eedc3cd5a2a75bb94727dc6578c6efe3d618b\ \ yarav3.4.0.tar.gz > sha256sum-yara && \
  sha256sum -c sha256sum-yara && \

  tar vxzf yarav3.4.0.tar.gz && \
  cd yara-3.4.0 && \
  ./bootstrap.sh && \
  ./configure && \
  make && \
  make install && \

  cd yara-python/ && \
  python setup.py build && \
  python setup.py install && \
  cd /tmp && \

# Retrieve pyexiftool, verify known good hash and install pyexiftool
  wget -O pyexiftool-master.zip https://github.com/smarnach/pyexiftool/archive/master.zip && \
  echo c243efbd226ad00333d03d16a39dc08ceb2ad277bd21b5247a2821156097debd\ \ pyexiftool-master.zip > sha256sum-pyexiftool && \
  sha256sum -c sha256sum-pyexiftool && \

  unzip pyexiftool-master.zip && \
  cd pyexiftool-master/ && \
  python setup.py build && \
  python setup.py install && \
  cd /tmp && \

# Retrieve current version of pefile via wget, verify known good hash and install pefile
  wget "http://pefile.googlecode.com/files/pefile-1.2.10-139.tar.gz" && \
  echo 8b7c5d853c97a923d0f6e128d0ae76b962aa75fd608d552f5a32e46276908a16\ \ pefile-1.2.10-139.tar.gz > sha256sum-pefile && \
  sha256sum -c sha256sum-pefile && \

  tar vxzf pefile-1.2.10-139.tar.gz && \
  cd pefile-1.2.10-139 && \
  python setup.py build && \
  python setup.py install && \
  cd /tmp && \

# Retrieve current version of jq via wget, verify known good hash and move to /usr/local/bin
  wget -O jq "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" && \
  echo c6b3a7d7d3e7b70c6f51b706a3b90bd01833846c54d32ca32f0027f00226ff6d\ \ jq > sha256sum-jq && \
  sha256sum -c sha256sum-jq && \
  chmod 755 jq && \
  mv jq /usr/local/bin/

# Install additional dependencies
RUN cd /tmp && \
  pip install fluent-logger \
  interruptingcow \
  olefile \
  pylzma \
  py-unrar2 \
  ssdeep

# Add nonroot user, clone repo and setup environment
RUN groupadd -r nonroot && \
  useradd -r -g nonroot -d /home/nonroot -s /sbin/nologin -c "Nonroot User" nonroot && \
  mkdir /home/nonroot && \
  chown -R nonroot:nonroot /home/nonroot

# Clone Laika BOSS from GitHub as nonroot user
USER nonroot
RUN cd /home/nonroot && \
  git clone https://github.com/lmco/laikaboss.git

# Run setup script to install Laika BOSS framework, client library, modules and associated scripts (laika.py, laikad.py, cloudscan.py)
USER root
RUN cd /home/nonroot/laikaboss/ && \
  python setup.py build && \
  python setup.py install

# Clean up and run ldconfig
RUN ldconfig && \
  apt-get remove -y --purge automake build-essential libtool && \
  apt-get autoremove -y --purge && \
  apt-get clean -y && \
  rm -rf /var/lib/apt/lists/*

USER nonroot
ENV HOME /home/nonroot
ENV USER nonroot
WORKDIR /home/nonroot/workdir

ENTRYPOINT echo "To run the standalone scanner, execute laika.py against a file like so:" && printf "\n""laika.py <filename> | jq -C . | less -r" && printf "\n\n""To run the networked instance, first execute laikad.py and use cloudscan against like so:" && printf "\n\n""laikad.py &" && printf "\n\n""cloudscan.py <filename> | jq -C . | less -r" && printf "\n\n" && /bin/bash
