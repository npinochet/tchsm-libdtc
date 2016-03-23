#!/bin/sh

sudo apt-get update -qq

sudo apt-get install -y check
sudo apt-get install -y libjson-c-dev
sudo apt-get install -y libconfig-dev
sudo apt-get install -y libsqlite3-dev
sudo apt-get install -y uuid-dev


wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.2.tar.gz
sudo tar -xzC /opt -f libsodium-1.0.2.tar.gz

wget http://download.zeromq.org/zeromq-4.1.4.tar.gz
sudo tar -xzC /opt -f zeromq-4.1.4.tar.gz

cd /opt/libsodium-1.0.2/ && sudo ./configure && sudo make && sudo make install

cd /opt/zeromq-4.1.4.tar.gz && sudo ./configure --with-libsodium && sudo make && sudo make install

