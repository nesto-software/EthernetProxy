#!/bin/bash

# libpcap
sudo apt-get install -y libpcap0.8
sudo ln -s /usr/lib/arm-linux-gnueabihf/libpcap.so.0.8 /usr/lib/arm-linux-gnueabihf/libpcap.so.1

# expecting openssl version 1.1.1d
sudo apt install -y openssl

# libzmq
sudo apt install -y libzmq3-dev
