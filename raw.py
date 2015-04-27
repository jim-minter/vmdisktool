#!/usr/bin/python

import base


class RawWriter(base.FileBase):
    def create(self, fn, size):
        self.f = open(fn, "w")
        self.f.truncate(size)

    def write_sector(self, sec, data):
        if data is None:
            return

        if len(data) != 1 << 9:
            raise Exception()

        self.pwrite(sec << 9, data)
