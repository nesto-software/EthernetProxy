#!/bin/bash

sudo rm /tmp/outdir/*

ncat -k -l 127.0.0.1 19000&
echo "test\ntest" | ncat 127.0.0.1 19000
