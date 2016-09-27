# Distributed Threshold Cryptography [![Build Status](https://travis-ci.org/niclabs/tchsm-libdtc.svg?branch=master)](https://travis-ci.org/niclabs/tchsm-libdtc)

The Distributed Threshold Cryptography library is mainly a PKCS#11 distributed implementation using the [threshold library](https://github.com/niclabs/tchsm-libtc), both libraries conform the Threshold Cryptography HSM project.

It contains two APIs, the PKCS#11 standard and our own API described at [dtc.h](https://github.com/niclabs/tchsm-libdtc/blob/master/src/include/dtc.h). Also includes a node implementation, a daemond the library connect to in order to perform the cryptographic operations.

The project intend to be an alternative to a HSM and to other availables software alternatives as SoftHSM, the main idea behind is to provide security by using Threshold Cryptography. This allows to store the private key as many different key shares, distributed among nodes (possibly) at different locations, reducing the risk of key compromise, both physically and digitally.

## Install

This project is in its early development stage, be aware of this as security issues and bugs are likely to be there.

## Development


The development is being done mainly by engineers and interns at [NIC Research Labs Chile](http://niclabs.cl), suggestion, improvements and/or questions are appreciatted.

### Requirements

### Testing

### Unit Testing

### System Testing
