#!/usr/bin/env python3
"""J2: append unsolicited content to the body AFTER signing (l= weakness).
usage: j2_append.py SIGNED_FILE OUT_FILE"""
import sys

msg = open(sys.argv[1], "rb").read()
spam = (b"WIN A PRIZE visit spam.example NOW!!! LIMITED OFFER spam.example\r\n"
        b"more appended unsolicited content\r\n")
open(sys.argv[2], "wb").write(msg + spam)
print("appended", len(spam), "bytes to body")
