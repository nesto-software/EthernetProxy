#!/bin/bash

# libpcap
sudo apt-get install -y libpcap0.8=1.8.1-6
sudo ln /usr/lib/arm-linux-gnueabihf/libpcap.so.0.8 /usr/lib/arm-linux-gnueabihf/libpcap.so.1

# expecting openssl version 1.1.1d
sudo apt install -y openssl=1.1.1d-0+deb10u6+rpt1

# libzmq
sudo apt install -y libzmq3-dev=4.3.1-4+deb10u2