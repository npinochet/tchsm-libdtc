# Distributed Threshold Cryptography [![Build Status](https://travis-ci.org/niclabs/tchsm-libdtc.svg?branch=master)](https://travis-ci.org/niclabs/tchsm-libdtc)

The Distributed Threshold Cryptography library is mainly a PKCS#11 distributed implementation using the [threshold library](https://github.com/niclabs/tchsm-libtc), both libraries conform the Threshold Cryptography HSM project.

It contains two APIs, the PKCS#11 standard and our own API described at [dtc.h](https://github.com/niclabs/tchsm-libdtc/blob/master/src/include/dtc.h). Also includes a node implementation, a daemond the library connect to in order to perform the cryptographic operations.

The project intend to be an alternative to a HSM and to other availables software alternatives as SoftHSM, the main idea behind is to provide security by using Threshold Cryptography. This allows to store the private key as many different key shares, distributed among nodes (possibly) at different locations, reducing the risk of key compromise, both physically and digitally.

## Install

This project is in its early development stage, be aware of this as security issues and bugs are likely to be there.

We do provide a few [Dockerfiles](https://github.com/niclabs/docker/tree/master/tchsm) you can use directly or see how the software is installed.

### Requirements

*botan, json-c, libconfig, libuuid, libsodium, sqlite3, tchsm-libtc, zeromq*

### Installing

Once the requirements are met you can install the software by following the next steps.

```shell
git clone https://github.com/niclabs/tchsm-libdtc.git
cd tchsm-libdtc
mkdir build
cd build
cmake ..
make install
```

## Development

The development is being done mainly by engineers and interns at [NIC Research Labs Chile](http://niclabs.cl), suggestion, improvements and/or questions are appreciatted.

### Requirements

Beside install requirements, you will need: *check* to run unit testing, *openssl* and *python3* with some libraries listed at ./test/system_test/requirements.txt to run System Test.

### Testing

### Unit Testing

### System Testing
