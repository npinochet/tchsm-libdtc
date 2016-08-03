#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -y check
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y libconfig-dev
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y uuid-dev
sudo apt-get install -y libbotan1.10-dev


wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.9.tar.gz
tar -xzC /tmp -f libsodium-1.0.9.tar.gz

wget https://github.com/zeromq/zeromq4-1/releases/download/v4.1.4/zeromq-4.1.4.tar.gz
tar -xzC /tmp -f zeromq-4.1.4.tar.gz

wget https://github.com/niclabs/tchsm-libtc/archive/master.zip
unzip master.zip -d /tmp

cd /tmp/libsodium-1.0.9/ && ./configure && make && sudo make install

cd /tmp/zeromq-4.1.4 && ./configure --with-libsodium && make && sudo make install && sudo ldconfig

cd /tmp/tchsm-libtc-master && mkdir build && cd build && cmake .. && sudo make install
