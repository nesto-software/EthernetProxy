#!/bin/bash

mkdir /tmp/outdir
sudo ./src/tcpflow -D -o /tmp/outdir -i lo port 19000
