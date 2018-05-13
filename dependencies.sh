#!/usr/bin/env bash

sudo apt-get install git libpcap-dev libssl-dev cmake -y

cd /tmp/
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build
cd build
cmake .. -DLIBTINS_ENABLE_CXX11=1
make -j4
sudo make install
sudo ldconfig
