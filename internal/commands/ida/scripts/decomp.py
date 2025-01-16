#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys

import idaapi
import idautils
import idc


def do_decompile(f):
    return idaapi.decompile(f, flags=idaapi.DECOMP_NO_WAIT)


def main(addr: int):
    print(do_decompile(addr))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        addr = int(sys.argv[1], 16)
        idc.auto_wait()
        main(addr)
    else:
        print("Please provide an address as argument")
