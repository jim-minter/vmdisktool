#!/usr/bin/python

import base
import struct
import zlib


class VMDKStreamWriter(base.FileBase):
    MAGICNUMBER = 0x564d444b
    VERSION = 3
    FLAGS = 0x30001
    GRAINSIZE = 128
    DESCRIPTOROFFSET = 1
    NUMGTESPERGT = 512
    RGDOFFSET = 0
    OVERHEAD = 128
    UNCLEANSHUTDOWN = 0
    COMPRESSALGORITHM = 1

    MARKER_EOS = 0     # end of stream
    MARKER_GT = 1      # grain table
    MARKER_GD = 2      # grain directory
    MARKER_FOOTER = 3  # footer (repeat of header with final info)

    def __init__(self):
        super(VMDKStreamWriter, self).__init__()

        self.grain_directory = []
        self.grain_table = []

    def create(self, fn, size):
        self.f = open(fn, "w")
        self.size = size

        self.grain_directory_size = divro(size, 512 * self.GRAINSIZE *
                                          self.NUMGTESPERGT)

        self.descriptor = self.prepare_descriptor()
        self.write_header()
        self.write(self.descriptor)
        self.seek(self.OVERHEAD * 512)

    def close(self):
        if self.grain_table:
            self.write_grain_table()

        offset = self.write_grain_directory()

        self.write_marker(1, self.MARKER_FOOTER)
        self.write_header(offset)

        self.write_marker(0, self.MARKER_EOS)
        self.f.close()

    def write_header(self, gd_offset=(1 << 64) - 1):
        fmt = "=IIIQQQQIQQQBccccH"
        self.write(struct.pack(fmt, self.MAGICNUMBER, self.VERSION,
                               self.FLAGS, self.size >> 9, self.GRAINSIZE,
                               self.DESCRIPTOROFFSET,
                               len(self.descriptor) / 512, self.NUMGTESPERGT,
                               self.RGDOFFSET, gd_offset, self.OVERHEAD,
                               self.UNCLEANSHUTDOWN, '\n', ' ', '\r', '\n',
                               self.COMPRESSALGORITHM) +
                   ("\0" * (512 - struct.calcsize(fmt))))

    def prepare_descriptor(self):
        sectors = self.size >> 9
        cylinders = divro(sectors, (63 * 255))

        descriptor = '''# Disk DescriptorFile
version=1
CID=7e5b80a7
parentCID=ffffffff
createType="streamOptimized"

# Extent description
RDONLY %{sectors}s SPARSE "test-s001.vmdk"

# The Disk Data Base
#DDB
ddb.adapterType = "lsilogic"
ddb.geometry.sectors = "63"
ddb.geometry.heads = "255"
ddb.geometry.cylinders = "%{cylinders}s"
ddb.longContentID = "8f15b3d0009d9a3f456ff7b28d324d2a"
ddb.virtualHWVersion = "7"''' % {"sectors": str(sectors),
                                 "cylinders": str(cylinders)}

        return descriptor + "\0" * (512 - len(descriptor) & 511)

    def write_grain(self, grain, data):
        self.write_grain_precompressed(grain, compress(data))

    def write_grain_precompressed(self, grain, data):
        if data is None:
            self.grain_table.append(0)

        else:
            self.grain_table.append(self.fp >> 9)
            grain_marker = self.grain_marker(grain * self.GRAINSIZE,
                                             len(data))
            self.write(grain_marker)
            self.write(data)
            self.write("\0" * (512 - (len(grain_marker) + len(data)) & 511))

        if len(self.grain_table) == self.NUMGTESPERGT:
            self.write_grain_table()
            self.grain_table = []

    def write_marker(self, numSectors, marker_type):
        fmt = "=QII"
        self.write(struct.pack(fmt, numSectors, 0, marker_type) +
                   ("\0" * (512 - struct.calcsize(fmt))))

    def grain_marker(self, offset, size):
        return struct.pack("=QI", offset, size)

    def write_grain_table(self):
        grain_table = self.grain_table + \
            ([0] * (self.NUMGTESPERGT - len(self.grain_table)))
        empty_grain_table = [0] * self.NUMGTESPERGT

        if grain_table == empty_grain_table:
            offset = 0

        else:
            self.write_marker(self.NUMGTESPERGT / 128, self.MARKER_GT)
            offset = self.fp
            self.pwrite_LEULs(offset, grain_table)

        self.grain_directory.append(offset >> 9)

    def write_grain_directory(self):
        grain_directory = self.grain_directory + \
            ([0] * (128 - len(self.grain_directory) & 127))
        self.write_marker(len(grain_directory) / 128, self.MARKER_GD)
        offset = self.fp
        self.pwrite_LEULs(offset, grain_directory)
        return offset >> 9


def divro(n, d):
    (q, r) = divmod(n, d)
    return q + (r != 0)


def compress(data):
    if data is None:
        return data

    return zlib.compress(data)
