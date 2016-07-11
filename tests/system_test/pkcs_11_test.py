#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from os import environ

import Crypto.PublicKey.RSA as RSA
from PyKCS11 import *
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


def initialize(lib):
    """
    Initializes the PKCS11 library
    :return: The successfully loaded PKCS11 library
    """
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(lib)
    except PyKCS11Error:
        sys.stderr.write("ERROR: The library could not be loaded\n")
        sys.exit(1)

    return pkcs11


def create_new_keys(session):
    """
    Creates new keys
    :return: Both public and private keys
    """
    public_template = [
        (CKA['CKA_CLASS'], CKO['CKO_PUBLIC_KEY']),
        (CKA['CKA_TOKEN'], True),
        (CKA['CKA_PRIVATE'], False),
        (CKA['CKA_MODULUS_BITS'], 0x0400),
        (CKA['CKA_PUBLIC_EXPONENT'], (0x01, 0x00, 0x01)),
        (CKA['CKA_ENCRYPT'], True),
        (CKA['CKA_VERIFY'], True),
        (CKA['CKA_VERIFY_RECOVER'], True),
        (CKA['CKA_WRAP'], True),
        (CKA['CKA_LABEL'], "My Public Key"),
        (CKA['CKA_ID'], (KEY_ID,))
    ]

    private_template = [
        (CKA['CKA_CLASS'], CKO['CKO_PRIVATE_KEY']),
        (CKA['CKA_TOKEN'], True),
        (CKA['CKA_PRIVATE'], True),
        (CKA['CKA_DECRYPT'], True),
        (CKA['CKA_SIGN'], True),
        (CKA['CKA_SIGN_RECOVER'], True),
        (CKA['CKA_UNWRAP'], True),
        (CKA['CKA_ID'], (KEY_ID,))
    ]

    (public_key, private_key) = session.generateKeyPair(
        public_template, private_template)
    return public_key, private_key


def get_key(session):
    """
    Get previously created keys
    :return: Both public and private keys
    """
    private_key = session.findObjects(
        [(CKA['CKA_CLASS'], CKO['CKO_PRIVATE_KEY']), (CKA['CKA_ID'], (KEY_ID,))])[0]
    public_key = session.findObjects(
        [(CKA['CKA_CLASS'], CKO['CKO_PUBLIC_KEY']), (CKA['CKA_ID'], (KEY_ID,))])[0]

    return public_key, private_key


def sign_and_verify(session, content_filename, private_key, public_exponent, modulus):
    """
    Verifies that the signing process is OK
    :param content: Content of the file in binary
    :param private_key: Private key in the session
    """
    #file = open(content_filename, "rb") # with blah
    #content = file.read()
    with open(content_filename, 'rb') as f:
    	content = f.read()

    signature = bytes(session.sign(private_key, content,
                                   mecha=Mechanism(CKM['CKM_SHA256_RSA_PKCS_PSS'], None)))
    
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
        finalize(session)
        sys.stderr.write("ERROR: Signature doesn't verify.\n")
        exit(1)


def finalize(session):
    """
    Logouts and closes a session
    :param session: Session to be closed
    """
    session.logout()
    session.closeSession()


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

    if args.tchsm_config is not None:
        environ["TCHSM_CONFIG"] = args.tchsm_config
    if args.pykcs11lib is not None:
        environ["PYKCS11LIB"] = args.pykcs11lib

    if environ.get("TCHSM_CONFIG") is None:
        sys.stderr.write("ERROR: TCHSM_CONFIG is wrongly set.\n")
        sys.exit(1)
    if environ.get("PYKCS11LIB") is None:
        sys.stderr.write("ERROR: PYKCS11LIB is wrongly set.\n")
        sys.exit(1)

    lib = None
    pkcs11 = initialize(lib)
    first_slot = pkcs11.getSlotList()[0]

    session = pkcs11.openSession(
        first_slot,
        CKF['CKF_SERIAL_SESSION'] | CKF['CKF_RW_SESSION'])
    session.login(args.pin)

    if args.create_key:
        (public_key, private_key) = create_new_keys(session)
    else:
        (public_key, private_key) = get_key(session)

    public_exponent_as_byte_list = session.getAttributeValue(
        public_key, [CKA['CKA_PUBLIC_EXPONENT']])[0]
    modulus_as_byte_list = session.getAttributeValue(
        public_key, [CKA['CKA_MODULUS']])[0]

    public_exponent = int.from_bytes(
        public_exponent_as_byte_list,
        byteorder='big',
        signed=False)
    modulus = int.from_bytes(
        modulus_as_byte_list,
        byteorder='big',
        signed=False)

    if args.filename != "":
        for _ in range(0, args.sign_loops):
            sign_and_verify(
                session,
                args.filename,
                private_key,
                public_exponent,
                modulus)

    finalize(session)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
