#!/usr/bin/python

import struct
import sys

HEADER_FMT = ">LLQLLQLLQQLLQQQQLL"
HEADER_LENGTH = struct.calcsize(HEADER_FMT)

data = struct.unpack(HEADER_FMT, sys.stdin.read(HEADER_LENGTH))

for i, x in enumerate(["magic", "version", "backing_file_offset",
                       "backing_file_size", "cluster_bits", "size",
                       "crypt_method", "l1_size", "l1_table_offset",
                       "refcount_table_offset", "refcount_table_clusters",
                       "nb_snapshots", "snapshots_offset",
                       "incompatible_features", "compatible_features",
                       "autoclear_features", "refcount_order",
                       "header_length"]):
    print "%25s: %x" % (x, data[i])
