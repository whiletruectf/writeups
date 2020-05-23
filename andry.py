checks = [
        lambda x: (x + 7) * 0x50 + 6 == 6326,
        lambda x: x * 0xc + 0xf == 2259,
        lambda x: x * 4 + 0xf == 455,
        lambda x: ((x + 0x10) * 2 + 8) * 6 == 1848,
        lambda x: (x + 5) * 0x1518 == 275400,
        lambda x: (x + 6) * 8 + 0x19 == 745, 
        lambda x: (x + 2) * 7 + 6 == 1714,
        lambda x: (x + 10) * 6 + 0xe == 1076,
        lambda x: ((x + 6) * 9 + 10) * 9 == 12645,
        lambda x: (x + 9) * 8 + 8 == 2120,
        lambda x: x * 0x310 == 153664,
        lambda x: (((x + 1) * 9 + 3) * 5 + 6) == 10371,
        lambda x: (x * 0x240 + 0xd) == 37453,
        lambda x: ((x * 0xfc + 6) * 4) == 203640,
        lambda x: x * 0xb64 == 691092,
        lambda x: (x + 7) * 0x1b0 == 36288,
        lambda x: (x + 4) * 0x32 + 3 == 753,
        lambda x: (x * 8 + 0x13) == 2011,
        lambda x: ((x * 0x32 + 10) * 9 + 9) == 59949,
        lambda x: (x + 4) * 0x50 + 2 == 18082,
        lambda x: (x + 10) * 6 + 0x10 == 538,
        lambda x: (x + 8) * 0xb4 == 12420,
        lambda x: (x + 2) * 0x14 + 9 == 2529,
        lambda x: (x + 0x14) * 10 == 1130,
        lambda x: ((x + 5) * 6 + 7) * 4 == 6076,
        lambda x: (x + 5) * 0xb4 + 2 == 11702,
        lambda x: (x * 9 + 7) * 0x15 + 9 == 47217,
        lambda x: (x + 0x24) * 8 == 1056,
        lambda x: x * 2 + 9 == 207,
        lambda x: ((x + 2) * 0x10 + 7) * 5 == 11315,
        lambda x: (x * 5 + 6) * 7 + 9 == 2676,
        lambda x: x + 0x13 == 261
        ]

key = []
for func in checks:
    for i in range(256):
        if func(i):
            key.append(int(hex(i)[2:].zfill(2), 16))
assert len(key) == 32

with open("enc_payload", "rb") as f:
    data = f.read()
dec = ""
with open("dalvik", "wb") as f:
    for i, byte in enumerate(data):
        f.write(bytes([byte ^ key[i % len(key)]]))

