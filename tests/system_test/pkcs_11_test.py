#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
from os import environ

import Crypto.PublicKey.RSA as RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from PyKCS11 import *

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
        sys.stderr("ERROR: The library could not be loaded\n")
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


def sign_and_verify(session, content, private_key, public_exponent, modulus):
    """
    Verifies that the signing process is OK
    :param content: Content of the file in binary
    :param private_key: Private key in the session
    """
    signature = bytes(session.sign(private_key, content,
                                   mecha=Mechanism(CKM['CKM_SHA256_RSA_PKCS_PSS'], None)))

    new_hash = SHA256.new()
    new_hash.update(content)

    public_key = RSA.construct((modulus, public_exponent))
    verifier = PKCS1_PSS.new(public_key)
    check_verify = verifier.verify(new_hash, signature)

    if not check_verify:
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
    args = parser.parse_args()

    if environ.get("TCHSM_CONFIG") is None:
        sys.stderr("ERROR: TCHSM_CONFIG is not set.\n")
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
        file = open(args.filename, "rb")
        content = file.read()

        for _ in range(0, args.sign_loops):
            sign_and_verify(
                session,
                content,
                private_key,
                public_exponent,
                modulus)

    finalize(session)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
