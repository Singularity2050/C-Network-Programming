# C-programming

Environment : Max OS X

Library : Packet Capture Library (Can run Linux + Windows + Max OS X)

**How to install Packet Capture Library? **

**Mac OS X : brew install libpcap**

**Linux : sudo apt-get install libcap-dev**

**Windows : https://www.winpcap.org/install/default.htm , https://www.winpcap.org/devel.htm , and set Windows Environment**

If you want to run the code on Windows OS, then remove "#define __linux__" line

Compile Machine: gcc

Ex) gcc -o exefile arp.c ./IP/ip.c ... ./ARP/arp.c -lpcap
