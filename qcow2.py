#!/usr/bin/python

import base
import struct
import zlib


class QCow2Base(base.FileBase):
    MAGIC = 0x514649fb
    VERSION = 3
    CRYPT_METHOD = 0
    NB_SNAPSHOTS = 0
    SNAPSHOTS_OFFSET = 0
    INCOMPATIBLE_FEATURES = 0
    COMPATIBLE_FEATURES = 0
    AUTOCLEAR_FEATURES = 0
    REFCOUNT_ORDER = 4

    HEADER_FMT = ">LLQLLQLLQQLLQQQQLL"
    HEADER_LENGTH = struct.calcsize(HEADER_FMT)

    COMPRESSED = 1 << 62
    COPIED = 1 << 63

    def new_l2_table(self):
        return [0] * (1 << self.cluster_bits - 3)

    def offsets(self, cluster):
        return (cluster >> self.cluster_bits - 3,
                cluster & (1 << self.cluster_bits - 3) - 1)

    def set_cluster_bits(self, cluster_bits):
        self.cluster_bits = cluster_bits


class QCow2Reader(QCow2Base):
    empty_sector = "\0" * (1 << 9)

    def __init__(self):
        super(QCow2Reader, self).__init__()
        self.r = None
        self.ccache = [None, None]

    def open(self, fn):
        self.f = open(fn, "r")
        self.read_header()

        self.empty_cluster = "\0" * (1 << self.cluster_bits)

        if self.backing_file:
            self.r = QCow2Reader()
            self.r.open(self.backing_file)
            if self.cluster_bits != self.r.cluster_bits or \
               self.size != self.r.size:
                raise Exception()

    def read_header(self):
        (magic, version, self.backing_file_offset, self.backing_file_size,
         self.cluster_bits, self.size, crypt_method, self.l1_size,
         self.l1_table_offset, self.refcount_table_offset,
         self.refcount_table_clusters, nb_snapshots, snapshots_offset,
         incompatible_features, compatible_features,
         autoclear_features, refcount_order, header_length) \
            = struct.unpack(self.HEADER_FMT, self.f.read(self.HEADER_LENGTH))

        if (magic, version, crypt_method, nb_snapshots, snapshots_offset,
            incompatible_features, compatible_features, autoclear_features,
            refcount_order, header_length) != \
            (self.MAGIC, self.VERSION, self.CRYPT_METHOD, self.NB_SNAPSHOTS,
             self.SNAPSHOTS_OFFSET, self.INCOMPATIBLE_FEATURES,
             self.COMPATIBLE_FEATURES, self.AUTOCLEAR_FEATURES,
             self.REFCOUNT_ORDER, self.HEADER_LENGTH):
            raise Exception()

        self.backing_file = self.pread(self.backing_file_offset,
                                       self.backing_file_size)

        self.l1_table = []
        for l1_entry in self.preadULLs(self.l1_table_offset, self.l1_size):
            if l1_entry:
                l1_entry = self.preadULLs(l1_entry & ~self.COPIED,
                                          1 << self.cluster_bits - 3)
            else:
                l1_entry = self.new_l2_table()

            self.l1_table.append(l1_entry)

    def _read_cluster(self, cluster):
        (l1_offset, l2_offset) = self.offsets(cluster)
        l2_entry = self.l1_table[l1_offset][l2_offset]

        if not l2_entry:
            if self.r:
                return self.r._read_cluster(cluster)
            else:
                return None

        if l2_entry & self.COMPRESSED:
            x = 62 - (self.cluster_bits - 8)
            offset = l2_entry & (1 << x) - 1
            size = 512 * ((l2_entry >> x) & (1 << (self.cluster_bits - 8)) - 1)

            data = decompress(self.pread(offset, size), 1 << self.cluster_bits)

        else:
            data = self.pread(l2_entry & ~self.COPIED, 1 << self.cluster_bits)

        if data == self.empty_cluster:
            data = None

        return data

    def read_cluster(self, cluster):
        if self.ccache[0] != cluster:
            self.ccache = [cluster, self._read_cluster(cluster)]
        return self.ccache[1]

    def read_sector(self, sec):
        cluster = sec >> self.cluster_bits - 9

        data = self.read_cluster(cluster)

        if data:
            offset = sec << 9 & (1 << self.cluster_bits) - 1
            data = data[offset:offset + 512]

            if data == self.empty_sector:
                data = None

        return data


class QCow2Writer(QCow2Base):
    def __init__(self):
        super(QCow2Writer, self).__init__()
        self.rc_table = [1]  # pre-allocate header
        self.backing_file_offset = 0
        self.backing_file_size = 0
        self.cluster_bits = 16
        self.l1_table_offset = self.alloc_cluster()
        self.refcount_table_offset = self.alloc_cluster()
        self.refcount_table_clusters = 1
        self.bytes_remaining = 0

    def alloc_cluster(self):
        offset = len(self.rc_table) << self.cluster_bits
        self.rc_table.append(1)
        return offset

    def write_header(self):
        self.pwrite(0, struct.pack(self.HEADER_FMT, self.MAGIC, self.VERSION,
                                   self.backing_file_offset,
                                   self.backing_file_size, self.cluster_bits,
                                   self.size, self.CRYPT_METHOD, self.l1_size,
                                   self.l1_table_offset,
                                   self.refcount_table_offset,
                                   self.refcount_table_clusters,
                                   self.NB_SNAPSHOTS, self.SNAPSHOTS_OFFSET,
                                   self.INCOMPATIBLE_FEATURES,
                                   self.COMPATIBLE_FEATURES,
                                   self.AUTOCLEAR_FEATURES,
                                   self.REFCOUNT_ORDER,
                                   self.HEADER_LENGTH))

    def write_rc(self):
        rc_table = []
        i = 0
        while i < len(self.rc_table):
            offset = self.alloc_cluster()
            data = self.rc_table[i:][:1 << self.cluster_bits - 1]
            self.pwrite_BEUSs(offset, data)
            rc_table.append(offset)
            i += len(data)

        self.pwrite_BEULLs(self.refcount_table_offset, rc_table)

    def write_l2_table(self, l2_table):
        offset = self.alloc_cluster()
        self.pwrite_BEULLs(offset, l2_table)
        return offset

    def write_l1_table(self):
        for i in range(len(self.l1_table)):
            if self.l1_table[i]:
                offset = self.write_l2_table(self.l1_table[i])
                self.l1_table[i] = offset | self.COPIED

        self.pwrite_BEULLs(self.l1_table_offset, self.l1_table)

    def set_l2_entry(self, cluster, entry):
        (l1, l2) = self.offsets(cluster)
        if not self.l1_table[l1]:
            self.l1_table[l1] = self.new_l2_table()

        self.l1_table[l1][l2] = entry

    def write_cluster_uncompressed(self, cluster, data):
        if data is None:
            return

        offset = self.alloc_cluster()
        self.set_l2_entry(cluster, offset | self.COPIED)
        self.pwrite(offset, data)

    def write_cluster_compressed(self, cluster, data):
        self.write_cluster_precompressed(self, cluster, compress(data))

    def write_cluster_precompressed(self, cluster, data):
        if data is None:
            return

        x = 62 - (self.cluster_bits - 8)

        self.set_l2_entry(cluster,
                          self.fp | (len(data) << x - 9) | self.COMPRESSED)

        if self.bytes_remaining:
            self.rc_table[-1] += 1

        while self.bytes_remaining <= len(data):
            self.alloc_cluster()
            self.bytes_remaining += 1 << self.cluster_bits

        self.write(data)
        self.bytes_remaining -= len(data)

    def create(self, fn, size, compressed=False):
        self.f = open(fn, "w")
        self.size = size

        if compressed:
            self.seek(len(self.rc_table) << self.cluster_bits)
            self.write_cluster = self.write_cluster_compressed
        else:
            self.write_cluster = self.write_cluster_uncompressed

        self.l1_size = divro(self.size, 1 << 2 * self.cluster_bits - 3)
        self.l1_table = [0] * self.l1_size

    def close(self):
        self.write_l1_table()
        self.write_rc()
        self.write_header()
        self.f.close()


def compress(data):
    if data is None:
        return data

    z = zlib.compressobj(9, zlib.DEFLATED, -12)
    data = z.compress(data) + z.flush()
    return data + "\0" * (512 - len(data) & 511)


def decompress(data, max_length):
    z = zlib.decompressobj(-12)
    return z.decompress(data, max_length)


def divro(n, d):
    (q, r) = divmod(n, d)
    return q + (r != 0)
