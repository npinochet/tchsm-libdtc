#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import array
import codecs
from os import environ
import sys

import Crypto.PublicKey.RSA as RSA
import PyKCS11
from subprocess import Popen, PIPE

"""
Replicates the PKCS11 test, which is a basic signing process test.
"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"


DEFAULT_PIN = "1234"
DEFAULT_AMOUNT = 1
KEY_ID = 0x22

class PKCS11TestException(Exception):
    pass

class PKCS11Test:
    def __init__(self, pin, tchsm_config = None, pykcs11lib = None, lib = None):
        if(tchsm_config is not None):
            environ["TCHSM_CONFIG"] = tchsm_config
        if(pykcs11lib is not None):
            environ["PYKCS11LIB"] = pykcs11lib
                 
        self.pkcs11 = self.initialize(lib)
        try:
            first_slot = self.pkcs11.getSlotList()[0]

            self.session = self.pkcs11.openSession(first_slot,
                PyKCS11.CKF['CKF_SERIAL_SESSION'] | PyKCS11.CKF['CKF_RW_SESSION'])
            self.session.login(pin)
        except PyKCS11.PyKCS11Error as e:
            raise PKCS11TestException("ERROR: Get slot list failed")
        

    def initialize(self, lib):
        """
        Initializes the PKCS11 library
        """
        pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            pkcs11.load(lib)
        except PyKCS11Error:
            sys.stderr.write("ERROR: The library could not be loaded\n")
            raise PKCS11Exception("ERROR: The library could not be loaded")

        return pkcs11

    def create_new_keys(self):
        """
        Creates new keys
        :return: Both public and private keys
        """
        public_template = [
            (PyKCS11.CKA['CKA_CLASS'], PyKCS11.CKO['CKO_PUBLIC_KEY']),
            (PyKCS11.CKA['CKA_TOKEN'], True),
            (PyKCS11.CKA['CKA_PRIVATE'], False),
            (PyKCS11.CKA['CKA_MODULUS_BITS'], 0x0400),
            (PyKCS11.CKA['CKA_PUBLIC_EXPONENT'], (0x01, 0x00, 0x01)),
            (PyKCS11.CKA['CKA_ENCRYPT'], True),
            (PyKCS11.CKA['CKA_VERIFY'], True),
            (PyKCS11.CKA['CKA_VERIFY_RECOVER'], True),
            (PyKCS11.CKA['CKA_WRAP'], True),
            (PyKCS11.CKA['CKA_LABEL'], "My Public Key"),
            (PyKCS11.CKA['CKA_ID'], (KEY_ID,))
        ]

        private_template = [
            (PyKCS11.CKA['CKA_CLASS'], PyKCS11.CKO['CKO_PRIVATE_KEY']),
            (PyKCS11.CKA['CKA_TOKEN'], True),
            (PyKCS11.CKA['CKA_PRIVATE'], True),
            (PyKCS11.CKA['CKA_DECRYPT'], True),
            (PyKCS11.CKA['CKA_SIGN'], True),
            (PyKCS11.CKA['CKA_SIGN_RECOVER'], True),
            (PyKCS11.CKA['CKA_UNWRAP'], True),
            (PyKCS11.CKA['CKA_ID'], (KEY_ID,))
        ]

        (public_key, private_key) = self.session.generateKeyPair(
            public_template, private_template)
        return public_key, private_key


    def get_key(self):
        """
        Get previously created keys
        :return: Both public and private keys
        """
        private_key = self.session.findObjects(
            [(CKA['CKA_CLASS'], PyKCS11.CKO['CKO_PRIVATE_KEY']), (PyKCS11.CKA['CKA_ID'], (KEY_ID,))])[0]
        public_key = self.session.findObjects(
            [(CKA['CKA_CLASS'], PyKCS11.CKO['CKO_PUBLIC_KEY']), (PyKCS11.CKA['CKA_ID'], (KEY_ID,))])[0]

        return public_key, private_key

    def sign_and_verify(self, content_filename, private_key, public_exponent, modulus):
        """
        Verifies that the signing process is OK
        :param content: Content of the file in binary
        :param private_key: Private key in the session
        :param public_exponent: Public exponent associated with the private_key
        :param modulus: modulus associated with the private_key
        """
        with open(content_filename, 'rb') as f:
            content = f.read()

        signature = bytes(self.session.sign(private_key, content,
                                       mecha=PyKCS11.Mechanism(PyKCS11.CKM['CKM_SHA256_RSA_PKCS_PSS'], None)))

        signature_file_name = 'signature'
        with open(signature_file_name, 'wb') as f:
            f.write(signature)

        public_key = RSA.construct((modulus, public_exponent))

        public_key_file_name = 'pkey.pem'
        with open(public_key_file_name, 'wb') as f:
            f.write(public_key.exportKey())

        command_list = ['openssl',
                        'dgst',
                        '-sha256',
                        '-sigopt',
                        'rsa_padding_mode:pss',
                        '-verify',
                        public_key_file_name,
                        '-signature',
                        signature_file_name,
                        content_filename ]

        openssl_process = Popen(command_list, stdout=PIPE, stderr=PIPE)
        stdout, stderr = openssl_process.communicate()

        if openssl_process.returncode != 0:
            self.finalize()
            sys.stderr.write("ERROR: Signature doesn't verify.\n")
            raise PKCS11TestException("ERROR: Signature doesn't verify.")


    def finalize(self):
        """
        Logouts and closes the session
        """
        self.session.logout()
        self.session.closeSession()

    def run(self, filename, create_key, sign_loops):
        if environ.get("TCHSM_CONFIG") is None:
            sys.stderr.write("ERROR: TCHSM_CONFIG is wrongly set.\n")
            raise PKCS11TestException("ERROR: TCHSM_CONFIG is wrongly set.")
        if environ.get("PYKCS11LIB") is None:
            sys.stderr.write("ERROR: PYKCS11LIB is wrongly set.\n")
            raise PKCS11TestException("ERROR: PYKCS11LIB is wrongly set.")

        if create_key:
            (public_key, private_key) = self.create_new_keys()
        else:
            (public_key, private_key) = self.get_key()

        public_exponent_as_byte_list = self.session.getAttributeValue(
            public_key, [PyKCS11.CKA['CKA_PUBLIC_EXPONENT']])[0]
        modulus_as_byte_list = self.session.getAttributeValue(
            public_key, [PyKCS11.CKA['CKA_MODULUS']])[0]

        public_exponent = int(codecs.encode(
                array.array('B', public_exponent_as_byte_list), 'hex'), 16)
        modulus = int(codecs.encode(
                array.array('B', modulus_as_byte_list), 'hex'), 16)

        if filename != "":
            for i in range(0, sign_loops):
                self.sign_and_verify(
                    filename,
                    private_key,
                    public_exponent,
                    modulus)

        self.finalize()
        return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description="System Testing")
    parser.add_argument("-c",
                        "--create_key",
                        help="If this is specified, a new key will be added",
                        default=False,
                        action="store_true")
    parser.add_argument("-f",
                        "--filename",
                        help="Path of the file to sign",
                        default="",
                        type=str)
    parser.add_argument("-l",
                        "--pykcs11lib",
                        help="Value of the PYKCS11LIB env variable",
                        type=str)
    parser.add_argument("-n",
                        "--sign_loops",
                        help="Amount of times the signing process will occur",
                        default=DEFAULT_AMOUNT,
                        type=int)
    parser.add_argument("-p",
                        "--pin",
                        help="Specifies the pin used in the session login",
                        default=DEFAULT_PIN,
                        type=str)
    parser.add_argument("-t",
                        "--tchsm_config",
                        help="Value of the TCHSM_CONFIG env variable",
                        type=str)
    args = parser.parse_args()

    tchsm_config = None
    pykcs11lib = None

    if args.tchsm_config is not None:
        tchsm_config = args.tchsm_config
    if args.pykcs11lib is not None:
        pykcs11lib = args.pykcs11lib
    return PKCS11Test(pin=args.pin, tchsm_config=tchsm_config, pykcs11lib=pykcs11lib).run(create_key = args.create_key,
     filename = args.filename, sign_loops=args.sign_loops)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
