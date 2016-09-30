# Distributed Threshold Cryptography [![Build Status](https://travis-ci.org/niclabs/tchsm-libdtc.svg?branch=master)](https://travis-ci.org/niclabs/tchsm-libdtc)

The Distributed Threshold Cryptography library is mainly a PKCS#11 distributed implementation using the [threshold library](https://github.com/niclabs/tchsm-libtc), both libraries conform the Threshold Cryptography HSM project.

It contains two APIs, the PKCS#11 standard and our own API described at [dtc.h](https://github.com/niclabs/tchsm-libdtc/blob/master/src/include/dtc.h). Also includes a node implementation, a daemon the library connect to in order to perform the cryptographic operations.

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
## Configuration

To perform authenticated and encrypted communication between the library and the nodes an offline configuration process must be done to configure the communication keys. We do provide a python script to generate the keys and the files with the configuration for the library and the nodes. In order to generate the files you just need to define the address and two ports available to use by the node:

```shell
python scripts/create_config.py <addr-node-1>:<p1_node-1>:<p2_node-1> .. <addr-node-n>:<p1_node-n>:<p2_node-n>
```

This will generate n + 2 configuration files, we'll use n + 1 of them. First all the nodei.conf files are the nodes configuration and cryptoki.conf is the library configuration file.
Inside the cryptoki.conf file there is a path to the database to be used by the library, change it as you need. (you can also set the ```-cdb``` flag in the script to set the variable.

There is a built in help in the script, python scrupt/create_config.py --help will print it in the stderr.

## Running

Once you have installed the library and got the configuration files you need to run the nodes and the libray. To run the node:

```shell
$ tchsm_node -c <path_to_the_nodei.conf>
```

The library however is not being run directly, so in order to make its configuration file reachable for it you need to set the TCHSM_CONFIG environment variable to the path of the cryptoki.conf file just generated.

## Supported mechanisms

Currently we do support the following PKCS#11 mechanisms:

* CKM_RSA_PKCS
* CKM_MD5_RSA_PKCS
* CKM_SHA1_RSA_PKCS
* CKM_SHA1_RSA_PKCS_PSS
* CKM_SHA256_RSA_PKCS
* CKM_SHA256_RSA_PKCS_PSS
* CKM_SHA384_RSA_PKCS
* CKM_SHA384_RSA_PKCS_PSS
* CKM_SHA512_RSA_PKCS
* CKM_SHA512_RSA_PKCS_PSS

## Development

The development is being done mainly by engineers and interns at [NIC Research Labs Chile](http://niclabs.cl), suggestion, improvements and/or questions are appreciatted.

### Requirements

Beside install requirements, you will need: *check* to run unit testing, *openssl* and *python3* with some libraries listed at ./test/system_test/requirements.txt to run System Test.

### Testing

### Unit Testing

### System Testing
