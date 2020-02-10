#!/usr/bin/env bash

sudo apt-get install git libpcap-dev libssl-dev cmake -y

if [ "$(whereis libtins)" == "libtins:" ]; then
  cd /tmp/ || exit
  git clone https://github.com/mfontanini/libtins
  cd libtins || exit
  mkdir build
  cd build || exit
  cmake .. -DLIBTINS_ENABLE_CXX11=1
  make -j4
  sudo make install
  sudo ldconfig
  cd /tmp/ || exit
  rm -rf libtins
fi