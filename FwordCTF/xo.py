from pwn import remote
import string

r = remote("xo.fword.wtf", 5554)
alpha = string.ascii_letters + string.digits + "{}_?!"
flag = ""

while True:
    for c in alpha:
        r.recvline()
        payload = len(flag) * "." + c
        r.sendline(payload)
        output = int(r.recvline().strip())
        if output == len(flag):
            flag += "."
            print(c, end="")
            break
