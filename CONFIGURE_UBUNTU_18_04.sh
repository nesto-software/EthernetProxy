#!/bin/bash

sudo apt-get update --fix-missing
sudo apt-get install -y emacs
sudo apt-get install -y git gcc g++ llvm-3.9 automake autoconf libpcap-dev openssl libssl-dev \
                        zlib1g-dev libcairo2 libcairo2-dev zlibc zlib1g-dev

sudo pip install --upgrade b2
mkdir -p /tmp/boost
pushd /tmp/boost
    wget -O boost_1_55_0.tar.gz "https://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.gz?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fboost%2Ffiles%2Fboost%2F1.55.0%2Fboost_1_55_0.tar.gz%2Fdownload%3Fuse_mirror%3Ddeac-riga&ts=1614225124"
    tar xfzv boost_1_55_0.tar.gz
    pushd boost_1_55_0
        sh bootstrap.sh
        ./b2
        sudo ./b2 install
popd
popd