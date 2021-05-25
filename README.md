Ethernet Proxy for Raspberry Pi (armhf)   
========

<p align="center">
  <img src=".github/imgs/project_logo.png">
</p>

[![https://github.com/nesto-software/ProxySuite](https://img.shields.io/badge/part%20of-ProxySuite-blue)](https://github.com/nesto-software/ProxySuite)


Heads Up!
------
This project is currently being refactored by Nesto.   
If you want to participate, feel free to reach out!   
For more information, please visit the [original README](./README.tcpflow.md).

Martin Löper `<martin.loeper@nesto-software.de>`

Development Status
------
<table>

  <tr><th>Variant</th><th>Status</th></tr>
  <tr><td>Software</td><td align="center">:gear:</td></tr>
  <tr><td>Hardware</td><td align="center">:heavy_check_mark:</td></tr>

</table>

The hardware variant runs without any known issues.   
We are currently not actively developing the software variant.
Thus, special hardware which leverages port mirroring is a prerequisite.

Conceptually, the software variant could be implemented using ip forwarding in the Linux kernel, setting up some iptables rules and capturing the packets using this codebase.

Setup
-------

We use the [TL-SG105E V4](https://www.tp-link.com/us/business-networking/easy-smart-switch/tl-sg105e/) for the reference design of our hardware variant. The larger [TL-SG108E V6](https://www.tp-link.com/us/business-networking/easy-smart-switch/tl-sg108e/) works as well.

Make sure to use a separate ethernet port for the capturing interface (eth-proxy) and the interface with internet & LAN access (eth0).
Since the Raspberry Pi 4B has one ethernet interface only, another one is needed. We tested the [Rankie USB Network Adapter](https://www.ijetech.com/product/usb-network-adapter-6421.html/) in this scenario and it appears to work just fine.
<!-- Start tcpflow as follows in order to capture printer traffic over AppSocket/JetDirect: `` -->

<img src=".github/imgs/setup.png">

Install via GitHub Releases Download (binary)
---------------------------------------------

| Method    | Command                                                                                           |
|:----------|:--------------------------------------------------------------------------------------------------|
| **curl**  | `bash -c "$(curl -fsSL https://raw.githubusercontent.com/nesto-software/EthernetProxy/master/scripts/install-from-release.sh)"` |
| **wget**  | `bash -c "$(wget -O- https://raw.githubusercontent.com/nesto-software/EthernetProxy/master/scripts/install-from-release.sh)"`   |
