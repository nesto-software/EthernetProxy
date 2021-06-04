# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.166.1/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version: debian-10, debian-9, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="buster"
ARG TOOLCHAIN_RELEASE=latest

FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}
LABEL org.opencontainers.image.source https://github.com/nesto-software/EthernetProxy

ADD https://raw.githubusercontent.com/nesto-software/cross-toolchain-armhf/master/scripts/install-from-release.sh \
    /tmp/install-cross-toolchain-armhf.sh

RUN chmod +x /tmp/install-cross-toolchain-armhf.sh \
    && /tmp/install-cross-toolchain-armhf.sh $TOOLCHAIN_RELEASE

ENV STAGING_DIR /usr/raspberry-build/staging
ENV TOOLCHAIN=arm-unknown-linux-gnueabi
ENV TOOLCHAIN_PATH=/opt/crosstool-ng/x-tools/${TOOLCHAIN}/bin
ENV PATH=${TOOLCHAIN_PATH}:${PATH}

RUN mkdir -p "${STAGING_DIR}"

RUN sudo apt-get update -y && apt-get install -y libtool autoconf automake g++

# zlib
RUN git clone https://github.com/madler/zlib.git /tmp/zlib && cd /tmp/zlib && git checkout cacf7f1d4e3d44d871b605da3b647f07d718623f \
        && CC=${TOOLCHAIN}-gcc ./configure --prefix=${STAGING_DIR}/usr/local \
        && make \
        && make install

# OpenSSL
RUN git clone https://github.com/openssl/openssl.git /tmp/openssl
RUN cd /tmp/openssl && git checkout OpenSSL_1_1_1d \
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

RUN git submodule update libs/tuple libs/numeric libs/smart_ptr libs/icl libs/optional libs/fusion libs/function_types libs/conversion libs/range libs/iterator libs/concept_check libs/chrono libs/date_time libs/timer libs/config libs/core libs/detail tools/build libs/system tools/boost_install libs/headers libs/assert libs/integer libs/static_assert libs/throw_exception libs/move libs/detail libs/preprocessor libs/type_traits libs/winapi libs/predef libs/mpl libs/utility libs/container_hash libs/io libs/ratio libs/rational libs/typeof

RUN ./bootstrap.sh
RUN sed -i "/using gcc/c\using gcc : arm : $TOOLCHAIN-g++ ;" project-config.jam
RUN ./b2 -toolset=$TOOLCHAIN address-model=32 architecture=arm --prefix=$STAGING_DIR/usr/local link=static install

# libpcap
RUN git clone https://github.com/the-tcpdump-group/libpcap.git /tmp/libpcap && cd /tmp/libpcap && git checkout libpcap-1.8.1
WORKDIR /tmp/libpcap

# install prerequisites, see: https://github.com/the-tcpdump-group/libpcap/blob/master/INSTALL.md
RUN apt-get install -y flex bison

RUN CC=${TOOLCHAIN}-gcc ./configure --host=$TOOLCHAIN --prefix=${STAGING_DIR}/usr/local --with-pcap=linux \
        && make \
        && make install

# the following is from usb-proxy:

# install libzmq
RUN git clone https://github.com/zeromq/libzmq.git /tmp/libzmq-2 && cd /tmp/libzmq-2 && git checkout 92282785ed8e3a954d379a0ac0e784dc29d94746
RUN apt-get install -y pkg-config

WORKDIR /tmp/libzmq-2/
RUN ./autogen.sh
# note: we must use both prefix options here because DESTPATH for make install places the files correctly but sets wrong pkg-config contents
RUN CC=${TOOLCHAIN}-gcc CXX=${TOOLCHAIN}-g++ AR=${TOOLCHAIN}-ar STRIP=${TOOLCHAIN}-strip RANLIB=${TOOLCHAIN}-ranlib ./configure --host=arm-none-linux-gnueabi --exec-prefix=$STAGING_DIR/usr/local --prefix=${STAGING_DIR}/usr/local --disable-curve-keygen 
RUN make
RUN make install

# install the CMAKE_TOOLCHAIN_FILE for our toolchain
ENV TOOLCHAIN_FILE /usr/raspberry-build/tmp/raspberry_pi_3_b_plus.cmake.tc
RUN mkdir -p /usr/raspberry-build/tmp/
COPY assets/armhf-cross-toolchain.cmake.tc $TOOLCHAIN_FILE

# install cppzmq
RUN git clone https://github.com/zeromq/cppzmq.git /tmp/cppzmq-2 && cd /tmp/cppzmq-2 && git checkout c591113bb7975e1be6fa6b0c758cacfe0411c66e

WORKDIR /tmp/cppzmq-2
RUN mkdir build
WORKDIR ./build

# install latest cmake binary directly (reason: cppzmq needs a feature of cmake 3.7+ regarding tarball name extraction)
RUN wget https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-Linux-x86_64.sh -P /tmp/
RUN chmod +x /tmp/cmake-3.19.4-Linux-x86_64.sh && mkdir /tmp/cmake && /tmp/cmake-3.19.4-Linux-x86_64.sh --skip-license --prefix=/tmp/cmake

# note: confirm pkg-content with pkg-config cli if in doubt: PKG_CONFIG_PATH=/usr/raspberry-build/staging/usr/local/lib/pkgconfig pkg-config libzmq --exists; echo $?
# note: without setting CMAKE_FIND_ROOT_PATH, the cmake find_* methods do not work as expected because of the toolchain file setting for CMAKE_FIND_ROOT_PATH_MODE_LIBRARY
RUN  CC=${TOOLCHAIN}-gcc CXX=${TOOLCHAIN}-g++ PKG_CONFIG_PATH=$STAGING_DIR/usr/local/lib/pkgconfig /tmp/cmake/bin/cmake .. "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE" "-DCMAKE_FIND_ROOT_PATH=$STAGING_DIR"
RUN  CC=${TOOLCHAIN}-gcc CXX=${TOOLCHAIN}-g++ make
RUN DESTDIR=${STAGING_DIR} make -j4 install

# install msgpack
RUN git clone https://github.com/msgpack/msgpack-c.git /tmp/msgpack-c

# install dependencies for msgpack: doxygen and boost
RUN sudo apt-get install -y doxygen

# note: we install boost twice to keep a clear separation between parts of boost needed for msgpack and those needed for tcpflow
RUN git clone https://github.com/boostorg/boost.git /tmp/boost-2 && cd /tmp/boost-2 && git checkout eeb338c73f90028145c52ec9de07b6eb2b2ad4e8
WORKDIR /tmp/boost-2

# install specific boost submodules
RUN git submodule init
# note: not sure which boost modules are actually required because they have nested dependencies - we install a bit more than probably required
# dependency graph: https://pdimov.github.io/boostdep-report/master/module-overview.html
# note: headers and date_time can be removed (probably)
# note: filesystem is required by tcpflow_gg
RUN git submodule update libs/chrono libs/date_time libs/timer libs/config libs/core libs/detail tools/build libs/system libs/filesystem libs/iterator tools/boost_install libs/headers libs/assert libs/integer libs/static_assert libs/throw_exception libs/move libs/detail libs/preprocessor libs/type_traits libs/winapi libs/predef libs/mpl libs/utility libs/container_hash libs/io  libs/ratio libs/rational libs/typeof
# the following are undocument but needed for tests!
RUN git submodule update libs/numeric/conversion libs/conversion libs/function_types libs/tuple libs/fusion libs/variant libs/type_index libs/smart_ptr libs/optional
RUN ./bootstrap.sh --with-libraries=chrono,system,timer,filesystem
RUN sed -i "/using gcc/c\using gcc : arm : $TOOLCHAIN-g++ ;" project-config.jam
RUN ./b2 -toolset=$TOOLCHAIN address-model=32 architecture=arm --prefix=$STAGING_DIR/usr/local link=static install

# install gtest
RUN apt-get install -y libgtest-dev
WORKDIR /usr/src/gtest
RUN DESTDIR=$STAGING_DIR cmake CMakeLists.txt
RUN make 

# note: we need a hash from branch cpp_master
WORKDIR /tmp/msgpack-c 
RUN git checkout 6b6a05e07cbadd4332bf16d48a09efb997756e4b
# note: cmake version must always be newer than boost version
RUN BOOST_ROOT=$STAGING_DIR/usr/local/ CXXFLAGS="-I${STAGING_DIR}/usr/local/include" /tmp/cmake/bin/cmake "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE" "-DCMAKE_FIND_ROOT_PATH=$STAGING_DIR" .
RUN DESTDIR=${STAGING_DIR} make install toolset=gcc-arm

# aws-greengrass-sdk-c
RUN git clone https://github.com/aws/aws-greengrass-core-sdk-c.git /tmp/aws-sdk
RUN cd /tmp/aws-sdk/ && git checkout a71613711438b48588e177f86ab322dd3992e780 && cd ./aws-greengrass-core-sdk-c && mkdir -p build && cd build && cmake "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE" "-DCMAKE_FIND_ROOT_PATH=$STAGING_DIR" .. && cmake "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE" "-DCMAKE_FIND_ROOT_PATH=$STAGING_DIR" --build . && sudo make install DESTDIR="${STAGING_DIR}"

# run the arm executable using qemu
# RUN apt install -y qemu-user-static