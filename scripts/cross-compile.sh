#!/bin/bash

bash bootstrap.sh

CC=${TOOLCHAIN}-gcc \
CXX=${TOOLCHAIN}-g++ \
AR=${TOOLCHAIN}-ar \
STRIP=${TOOLCHAIN}-strip \
RANLIB=${TOOLCHAIN}-ranlib \
CPPFLAGS="" \
LDFLAGS="" \
./configure \
    --host=arm-unknown-linux-gnueabi \
    --exec-prefix=$STAGING_DIR/usr/local \
    --prefix=${STAGING_DIR}/usr/local