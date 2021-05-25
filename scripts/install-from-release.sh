#!/bin/bash

set -e

FILE=/tmp/ethernet-proxy

# install deps if not available
bash -c "$(curl -fsSL https://raw.githubusercontent.com/nesto-software/EthernetProxy/master/scripts/install-dependencies.sh)"

echo "Downloading ethernet-proxy binary from latest GitHub release..."
curl -s https://api.github.com/repos/nesto-software/EthernetProxy/releases/tags/latest \
| grep "browser_download_url.*ethernetproxy\"" \
| cut -d : -f 2,3 \
| tr -d \" \
| wget -qi - -O "$FILE"

echo "Installing binary..."
sudo install -m 755 "${FILE}" "/usr/bin/ethernet-proxy"