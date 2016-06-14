#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import sys
from os import environ

import Crypto.PublicKey.RSA as RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from PyKCS11 import *

"""

"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"


DEFAULT_PIN = "1234"
DEFAULT_AMOUNT = 1

def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="System Testing")
    parser.add_argument("-c",
                        "--create_key",
                        help="",
                        default=False,
                        action="store_true")
    parser.add_argument("-f",
                        "--filename",
                        help="",
                        default="",
                        type=str)
    parser.add_argument("-n",
                        "--sign_loops",
                        help="",
                        default=DEFAULT_AMOUNT,
                        type=int)
    parser.add_argument("-p",
                        "--pin",
                        help="",
                        default=DEFAULT_PIN,
                        type=str)
    args = parser.parse_args()

    if environ.get("TCHSM_CONFIG") is None:
        sys.stderr("ERROR: TCHSM_CONFIG is not set")
        return 1

    lib = None
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)

    slot = pkcs11.getSlotList()[0]

    session = pkcs11.openSession(slot, CKF['CKF_SERIAL_SESSION'] | CKF['CKF_RW_SESSION'])
    session.login(args.pin)

    KEY_ID = 0x22

    if args.create_key:
        pubTemplate = [
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

        privTemplate = [
            (CKA['CKA_CLASS'], CKO['CKO_PRIVATE_KEY']),
            (CKA['CKA_TOKEN'], True),
            (CKA['CKA_PRIVATE'], True),
            (CKA['CKA_DECRYPT'], True),
            (CKA['CKA_SIGN'], True),
            (CKA['CKA_SIGN_RECOVER'], True),
            (CKA['CKA_UNWRAP'], True),
            (CKA['CKA_ID'], (KEY_ID,))
        ]

        (pubKey, privKey) = session.generateKeyPair(pubTemplate, privTemplate)
    else:
        privKey = session.findObjects([(CKA['CKA_CLASS'], CKO['CKO_PRIVATE_KEY']), (CKA['CKA_ID'], (KEY_ID,))])[0]
        pubKey = session.findObjects([(CKA['CKA_CLASS'], CKO['CKO_PUBLIC_KEY']), (CKA['CKA_ID'], (KEY_ID,))])[0]

    n_byte_list, e_byte_list = session.getAttributeValue(pubKey, [CKA['CKA_MODULUS'], CKA['CKA_PUBLIC_EXPONENT']])

    print(n_byte_list, e_byte_list)
    
    e = int.from_bytes(e_byte_list, byteorder='big', signed=False)
    n = int.from_bytes(n_byte_list, byteorder='big', signed=False)

    if args.filename != "":
        f = open(args.filename, "rb")
        toSign = "48656c6c6f20776f726c640d0a"
        content = f.read()
        for i in range(0, args.sign_loops):
            signature = bytes(session.sign(privKey, binascii.unhexlify(toSign),
                                           mecha=Mechanism(CKM['CKM_SHA256_RSA_PKCS_PSS'], None)))
            print(signature)

            h = SHA256.new()
            h.update(binascii.unhexlify(toSign))

            public_key = RSA.construct((n, e))
            verifier = PKCS1_PSS.new(public_key)
            verify = verifier.verify(h, signature)

            if not verify:
                session.logout()
                session.closeSession()
                sys.stderr.write("Error: Signature doesn't verify.\n")
                exit(1)

    session.logout()
    session.closeSession()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
