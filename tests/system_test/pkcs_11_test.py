#!/usr/bin/env python
# -*- coding: utf-8 -*-

import PyKCS11
import sys

"""

"""

__author__ = "Daniel Aviv"
__email__ = "daniel_avivnotario@hotmail.com"
__credits__ = ["Francisco Montoto", "Francisco Cifuentes"]
__status__ = "Development"


DEFAULT_PIN = 1234


def initialize(lib):
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)


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
                        type=str)
    parser.add_argument("-n",
                        "--amount_of_sign",
                        help="",
                        type=int)
    parser.add_argument("-p",
                        "--pin",
                        help="",
                        default=DEFAULT_PIN,
                        type=int)
    args = parser.parse_args()

    lib = None
    initialize(lib)

    print "Sekai-san, konnichiwa"
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
