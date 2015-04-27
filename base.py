#!/usr/bin/python

import struct


class FileBase(object):
    def __init__(self):
        self.fp = 0

    def pread(self, offset, size):
        self.seek(offset)
        return self.read(size)

    def preadULLs(self, offset, count):
        data = self.pread(offset, count * 8)
        return [struct.unpack(">Q", data[i:i + 8])[0]
                for i in range(0, len(data), 8)]

    def pwrite(self, offset, data):
        self.seek(offset)
        self.write(data)

    def pwrite_BEULLs(self, offset, data):
        self.pwrite(offset, "".join([struct.pack(">Q", x) for x in data]))

    def pwrite_LEULs(self, offset, data):
        self.pwrite(offset, "".join([struct.pack("<L", x) for x in data]))

    def pwrite_BEUSs(self, offset, data):
        self.pwrite(offset, "".join([struct.pack(">H", x) for x in data]))

    def read(self, size):
        data = self.f.read(size)
        self.fp += len(data)

        if len(data) != size:
            raise Exception()

        return data

    def seek(self, offset):
        if self.fp != offset:
            self.f.seek(offset)
            self.fp = offset

    def write(self, data):
        self.f.write(data)
        self.fp += len(data)
