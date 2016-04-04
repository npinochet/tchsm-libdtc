#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -y check
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y libconfig-dev
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y uuid-dev


wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.9.tar.gz
sudo tar -xzC /opt -f libsodium-1.0.9.tar.gz

wget http://download.zeromq.org/zeromq-4.1.4.tar.gz
sudo tar -xzC /opt -f zeromq-4.1.4.tar.gz

wget http://botan.randombit.net/releases/Botan-1.11.29.tgz
sudo tar -xzC /opt -f Botan-1.11.29.tgz

wget https://github.com/niclabs/tclib/archive/master.zip
sudo unzip master.zip -d /opt

cd /opt/libsodium-1.0.9/ && sudo ./configure && sudo make && sudo make install

cd /opt/zeromq-4.1.4 && sudo ./configure --with-libsodium && sudo make && sudo make install

cd /opt/tclib-master && sudo mkdir build && cd build && sudo cmake .. && sudo make install

cd /opt/Botan-1.11.29 && ./configure && make && sudo make install
