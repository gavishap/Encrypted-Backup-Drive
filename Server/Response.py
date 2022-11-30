import struct


class Response:
    def __init__(self, version, code, payload_size, payload):
        self.stream = bytearray(payload_size)
        self.stream[0] = version
        struct.pack_into("H", self.stream, 1, code)
        struct.pack_into("I", self.stream, 3, payload_size)
        self.stream[7:] = payload