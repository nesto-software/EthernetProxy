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

ADD https://raw.githubusercontent.com/nesto-software/SerialProxy/master/scripts/install-cross-toolchain-armhf.sh \
    /tmp/install-cross-toolchain-armhf.sh

RUN chmod +x /tmp/install-cross-toolchain-armhf.sh \
    && /tmp/install-cross-toolchain-armhf.sh

ENV TOOLCHAIN arm-unknown-linux-gnueabi
ENV STAGING_DIR /usr/raspberry-build/staging
ENV PATH="/opt/crosstool-ng/x-tools/${TOOLCHAIN}/bin:${PATH}"

RUN mkdir -p "${STAGING_DIR}"

# zlib
RUN git clone https://github.com/madler/zlib.git /tmp/zlib && cd /tmp/zlib && git checkout cacf7f1d4e3d44d871b605da3b647f07d718623f \
        && CC=${TOOLCHAIN}-gcc ./configure --prefix=${STAGING_DIR}/usr/local \
        && make \
        && make install

# OpenSSL
RUN git clone https://github.com/openssl/openssl.git /tmp/openssl
RUN cd /tmp/openssl && git checkout d7970dd963134534340ad00fa62cb1180daf5cb0 \
        && ./Configure linux-generic32 --cross-compile-prefix=/opt/crosstool-ng/x-tools/${TOOLCHAIN}/bin/arm-unknown-linux-gnueabi- --prefix=$STAGING_DIR/usr/local/ \
        && make \
        && make install

# boost: interval_map interval_set
RUN git clone https://github.com/boostorg/boost.git /tmp/boost && cd /tmp/boost && git checkout eeb338c73f90028145c52ec9de07b6eb2b2ad4e8
WORKDIR /tmp/boost

# install specific boost submodules
RUN git submodule init
# note: not sure which boost modules are actually required because they have nested dependencies - we install a bit more than probably required
# dependency graph: https://pdimov.github.io/boostdep-report/master/module-overview.html

RUN git submodule update libs/tuple libs/numeric libs/smart_ptr libs/icl libs/optional libs/fusion libs/function_types libs/conversion libs/range libs/iterator libs/concept_check libs/chrono libs/date_time libs/timer libs/config libs/core libs/detail tools/build libs/system tools/boost_install libs/headers libs/assert libs/integer libs/static_assert libs/throw_exception libs/move libs/detail libs/preprocessor libs/type_traits libs/winapi libs/predef libs/mpl libs/utility libs/container_hash libs/io  libs/ratio libs/rational libs/typeof

RUN ./bootstrap.sh
RUN sed -i "/using gcc/c\using gcc : arm : $TOOLCHAIN-g++ ;" project-config.jam
RUN ./b2 -toolset=$TOOLCHAIN address-model=32 architecture=arm --prefix=$STAGING_DIR/usr/local link=static install

# libpcap
RUN git clone https://github.com/the-tcpdump-group/libpcap.git /tmp/libpcap && cd /tmp/libpcap && git checkout f0aa2722d313bc91afc26b4f2eef0a461b89c586
WORKDIR /tmp/libpcap

# install prerequisites, see: https://github.com/the-tcpdump-group/libpcap/blob/master/INSTALL.md
RUN apt-get install -y flex bison

RUN CC=${TOOLCHAIN}-gcc ./configure --host=$TOOLCHAIN --prefix=${STAGING_DIR}/usr/local \
        && make \
        && make install