FROM ubuntu:xenial

COPY . /usr/src/bootstrap-dht
WORKDIR /usr/src/bootstrap-dht

RUN \
  apt-get update && \
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y install \
      build-essential \
      libboost-dev \
      libboost-system-dev \
      libboost-tools-dev \
  && \
  bjam release \
  && \
  DEBIAN_FRONTEND=noninteractive \
    apt-get -y purge --auto-remove \
      build-essential \
  && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/

ENTRYPOINT [ "./dht-bootstrap" ]
