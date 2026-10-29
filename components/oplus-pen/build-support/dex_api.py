# SPDX-License-Identifier: Apache-2.0
"""Read DEX method definitions and inheritance for the pinned donor ABI check."""
import struct
import zipfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        require(offset < len(data), "truncated DEX uleb128")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise ValueError("oversized DEX uleb128")


class DexApi:
    def __init__(self):
        self.references = set()
        self.definitions = set()
        self.classes = {}
        self.fields = {}

    def add_archive(self, path):
        with zipfile.ZipFile(path) as archive:
            names = [n for n in archive.namelist() if n.endswith('.dex')]
            require(bool(names), "archive has no DEX: " + str(path))
            for name in names:
                self.add_dex(archive.read(name))

    def add_dex(self, data):
        require(len(data) >= 112 and data[:4] == b'dex\n', "invalid DEX header")
        require(struct.unpack_from('<I', data, 32)[0] == len(data), "DEX file size mismatch")
        require(struct.unpack_from('<I', data, 40)[0] == 0x12345678, "unsupported DEX endian")
        def u32(p):
            require(0 <= p <= len(data) - 4, "DEX offset outside file")
            return struct.unpack_from('<I', data, p)[0]
        def table(p, size):
            count, offset = u32(p), u32(p + 4)
            require(count <= len(data) // size and offset + count * size <= len(data), "DEX table outside file")
            return range(count), offset
        count, offset = table(56, 4)
        strings = []
        for i in count:
            p = u32(offset + i * 4)
            _, p = uleb(data, p)
            end = data.find(b'\0', p)
            require(end >= p, "unterminated DEX string")
            strings.append(data[p:end].decode('utf-8', errors='replace'))
        count, offset = table(64, 4)
        types = [strings[u32(offset + i * 4)] for i in count]
        def type_list(p):
            if not p:
                return []
            count = u32(p)
            require(p + 4 + 2 * count <= len(data), "DEX type list outside file")
            return [types[struct.unpack_from('<H', data, p + 4 + 2 * j)[0]] for j in range(count)]
        count, offset = table(72, 12)
        protos = []
        for i in count:
            _, ret, params = struct.unpack_from('<III', data, offset + i * 12)
            protos.append('(' + ''.join(type_list(params)) + ')' + types[ret])
        count, offset = table(88, 8)
        methods = []
        for i in count:
            owner, proto, name = struct.unpack_from('<HHI', data, offset + i * 8)
            methods.append(types[owner] + '->' + strings[name] + protos[proto])
        self.references.update(methods)
        count, offset = table(80, 8)
        fields = []
        for i in count:
            owner, ty, name = struct.unpack_from('<HHI', data, offset + i * 8)
            fields.append(types[owner] + '->' + strings[name] + ':' + types[ty])
        def encoded(p):
            require(p < len(data), "truncated DEX encoded value")
            tag = data[p]; p += 1
            ty, size = tag & 31, (tag >> 5) + 1
            if ty == 0x1e:
                return None, p
            if ty == 0x1f:
                return bool(tag >> 5), p
            if ty == 0x1c:
                count, p = uleb(data, p); out = []
                for _ in range(count):
                    value, p = encoded(p); out.append(value)
                return out, p
            require(p + size <= len(data), "DEX encoded value outside file")
            value = int.from_bytes(data[p:p + size], 'little'); p += size
            return (strings[value] if ty == 0x17 else value), p
        count, offset = table(96, 32)
        for i in count:
            cl, _, parent, interfaces, _, _, p, static_values = struct.unpack_from('<8I', data, offset + i * 32)
            owner = types[cl]
            self.classes[owner] = ([] if parent == 0xffffffff else [types[parent]]) + type_list(interfaces)
            if not p:
                continue
            counts = []
            for _ in range(4):
                value, p = uleb(data, p); counts.append(value)
            static_fields = []
            for group, total in enumerate(counts[:2]):
                idx = 0
                for _ in range(total):
                    delta, p = uleb(data, p); idx += delta
                    _, p = uleb(data, p)
                    if group == 0:
                        static_fields.append(fields[idx])
            for total in counts[2:]:
                idx = 0
                for _ in range(total):
                    delta, p = uleb(data, p); idx += delta
                    _, p = uleb(data, p); _, p = uleb(data, p)
                    self.definitions.add(methods[idx])
            if static_values:
                total, p = uleb(data, static_values)
                require(total <= len(static_fields), "DEX static value count mismatch")
                for name in static_fields[:total]:
                    value, p = encoded(p); self.fields[name] = value

    def resolves(self, method, seen=None):
        if method in self.definitions:
            return True
        owner, member = method.split('->', 1)
        seen = set() if seen is None else seen
        if owner in seen or member.startswith('<init>'):
            return False
        seen.add(owner)
        return any(self.resolves(parent + '->' + member, seen) for parent in self.classes.get(owner, []))
