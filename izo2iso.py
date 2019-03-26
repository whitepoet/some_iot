import zlib
import struct
import binascii

with open('contents.izo', 'rb') as fin:
    izo_file = fin.read()

magic_script = izo_file[:0x80]
magic_header = struct.unpack('>I', izo_file[0x80:0x84])[0]
assert magic_header == 0x4000, 'header error: %s' % (
    binascii.hexlify(magic_header))
count = struct.unpack('>I', izo_file[0x84:0x88])[0]
print('[*] count: %d' % (count))

iso_file = open('contents.iso', 'wb')
offset = 0x88
start = struct.unpack('>Q', izo_file[offset:offset + 0x8])[0]
offset += 0x8
for i in range(count):
    end = struct.unpack('>Q', izo_file[offset:offset + 0x8])[0]
    print('[*] start: 0x%x, end:0x%x' % (start, end))
    iso_file.write(zlib.decompress(izo_file[start:end]))
    start = end
    offset += 0x8

iso_file.close()

print('[+] convert success!')
