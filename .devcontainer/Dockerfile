# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.166.1/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version: debian-10, debian-9, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
        && apt-get -y install --no-install-recommends libtool autoconf automake g++ libboost-all-dev libssl-dev libpcap-dev libcairo2-dev libpython2.7-dev

RUN git clone https://github.com/zeromq/libzmq.git /tmp/libzmq && cd /tmp/libzmq && git checkout 92282785ed8e3a954d379a0ac0e784dc29d94746 \
        && cd /tmp/libzmq/ \
        && ./autogen.sh \
        && ./configure \
        && make \
        && sudo make install

RUN git clone https://github.com/zeromq/cppzmq.git /tmp/cppzmq && cd /tmp/cppzmq && git checkout c591113bb7975e1be6fa6b0c758cacfe0411c66e \
        && cd /tmp/cppzmq \
        && mkdir build \
        && cd ./build \
        && cmake .. \
        && make \
        && sudo make -j4 install