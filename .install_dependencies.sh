#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -y check
sudo apt-get install -y libboost-all-dev
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y libconfig-dev
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y uuid-dev


wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.9.tar.gz
tar -xzC /tmp -f libsodium-1.0.9.tar.gz

wget http://download.zeromq.org/zeromq-4.1.4.tar.gz
tar -xzC /tmp -f zeromq-4.1.4.tar.gz

wget http://botan.randombit.net/releases/Botan-1.11.29.tgz
tar -xzC /tmp -f Botan-1.11.29.tgz

wget https://github.com/niclabs/tchsm-libtc/archive/master.zip
unzip master.zip -d /tmp

cd /tmp/libsodium-1.0.9/ && ./configure && make && sudo make install

cd /tmp/zeromq-4.1.4 && ./configure --with-libsodium && make && sudo make install

cd /tmp/tchsm-libtc-master && mkdir build && cd build && cmake .. && sudo make install

cd /tmp/Botan-1.11.29 && ./configure.py && make && sudo make install
